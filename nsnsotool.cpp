// Copyright (c) 2018, CBH <maodatou88@163.com>
// Licensed under the terms of the BSD 3-Clause License
// https://github.com/0CBH0/nsnsotool/blob/master/LICENSE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <lz4.h>
#include "nsnsotool.h"
#include "sha256.h"


using namespace std;

int decompress(FILE* in, FILE* out)
{
	NSOHeader nsoHeader;
	fread(&nsoHeader, sizeof(NSOHeader), 1, in);
	nsoHeader.flags = 0;
	fwrite(&nsoHeader, sizeof(NSOHeader), 1, out);
	tempa_u32 = 0;
	for (u32 i = 0; i < 0x18; i++) 
		fwrite(&tempa_u32, 4, 1, out);
	while ((u32)ftell(out) < nsoHeader.fileOffset_text) 
		putc(0, out);

	char* textData = new char[nsoHeader.cmpSize_text];
	char* dcmpTextData = new char[nsoHeader.dcmpSize_text];
	fseek(in, nsoHeader.fileOffset_text, 0);
	fread(textData, 1, nsoHeader.cmpSize_text, in);
	LZ4_decompress_safe(textData, dcmpTextData, nsoHeader.cmpSize_text, nsoHeader.dcmpSize_text);
	fwrite(dcmpTextData, 1, nsoHeader.dcmpSize_text, out);
	nsoHeader.cmpSize_text = nsoHeader.dcmpSize_text;

	char* rodataData = new char[nsoHeader.cmpSize_rodata];
	char* dcmpRodataData = new char[nsoHeader.dcmpSize_rodata];
	fseek(in, nsoHeader.fileOffset_rodata, 0);
	nsoHeader.fileOffset_rodata = ftell(out);
	fread(rodataData, 1, nsoHeader.cmpSize_rodata, in);
	LZ4_decompress_safe(rodataData, dcmpRodataData, nsoHeader.cmpSize_rodata, nsoHeader.dcmpSize_rodata);
	fwrite(dcmpRodataData, 1, nsoHeader.dcmpSize_rodata, out);
	nsoHeader.cmpSize_rodata = nsoHeader.dcmpSize_rodata;

	char* dataData = new char[nsoHeader.cmpSize_data];
	char* dcmpDataData = new char[nsoHeader.dcmpSize_data];
	fseek(in, nsoHeader.fileOffset_data, 0);
	nsoHeader.fileOffset_data = ftell(out);
	fread(dataData, 1, nsoHeader.cmpSize_data, in);
	LZ4_decompress_safe(dataData, dcmpDataData, nsoHeader.cmpSize_data, nsoHeader.dcmpSize_data);
	fwrite(dcmpDataData, 1, nsoHeader.dcmpSize_data, out);
	nsoHeader.cmpSize_data = nsoHeader.dcmpSize_data;

	rewind(out);
	fwrite(&nsoHeader, sizeof(NSOHeader), 1, out);
	delete[]textData;
	delete[]dcmpTextData;
	delete[]rodataData;
	delete[]dcmpRodataData;
	delete[]dataData;
	delete[]dcmpDataData;
	return 0;
}

int compress(FILE* in, FILE* out)
{
	NSOHeader nsoHeader;
	u8 sha256_text[32];
	u8 sha256_rodata[32];
	u8 sha256_data[32];

	fread(&nsoHeader, sizeof(NSOHeader), 1, in);
	nsoHeader.flags = 0x3F;
	fwrite(&nsoHeader, sizeof(NSOHeader), 1, out);
	tempa_u32 = 0;
	for (u32 i = 0; i < 0x18; i++) 
		fwrite(&tempa_u32, 4, 1, out);
	while ((u32)ftell(out) < nsoHeader.fileOffset_text) 
		putc(0, out);

	char* dcmpTextData = new char[nsoHeader.dcmpSize_text];
	fseek(in, nsoHeader.fileOffset_text, 0);
	fread(dcmpTextData, 1, nsoHeader.dcmpSize_text, in);
	calc_sha_256(sha256_text, dcmpTextData, nsoHeader.dcmpSize_text);
	char* textData = new char[LZ4_compressBound(nsoHeader.dcmpSize_text)];
	nsoHeader.cmpSize_text = LZ4_compress_default(dcmpTextData, textData, nsoHeader.dcmpSize_text, LZ4_compressBound(nsoHeader.dcmpSize_text));
	fwrite(textData, 1, nsoHeader.cmpSize_text, out);

	char* dcmpRodataData = new char[nsoHeader.dcmpSize_rodata];
	fseek(in, nsoHeader.fileOffset_rodata, 0);
	nsoHeader.fileOffset_rodata = ftell(out);
	fread(dcmpRodataData, 1, nsoHeader.dcmpSize_rodata, in);
	calc_sha_256(sha256_rodata, dcmpRodataData, nsoHeader.dcmpSize_rodata);
	char* rodataData = new char[LZ4_compressBound(nsoHeader.dcmpSize_rodata)];
	nsoHeader.cmpSize_rodata = LZ4_compress_default(dcmpRodataData, rodataData, nsoHeader.dcmpSize_rodata, LZ4_compressBound(nsoHeader.dcmpSize_rodata));
	fwrite(rodataData, 1, nsoHeader.cmpSize_rodata, out);

	char* dcmpDataData = new char[nsoHeader.dcmpSize_data];
	fseek(in, nsoHeader.fileOffset_data, 0);
	nsoHeader.fileOffset_data = ftell(out);
	fread(dcmpDataData, 1, nsoHeader.dcmpSize_data, in);
	calc_sha_256(sha256_data, dcmpDataData, nsoHeader.dcmpSize_data);
	char* dataData = new char[LZ4_compressBound(nsoHeader.dcmpSize_data)];
	nsoHeader.cmpSize_data = LZ4_compress_default(dcmpDataData, dataData, nsoHeader.dcmpSize_data, LZ4_compressBound(nsoHeader.dcmpSize_data));
	fwrite(dataData, 1, nsoHeader.cmpSize_data, out);

	rewind(out);
	fwrite(&nsoHeader, sizeof(NSOHeader), 1, out);
	fwrite(&sha256_text, 1, 0x20, out);
	fwrite(&sha256_rodata, 1, 0x20, out);
	fwrite(&sha256_data, 1, 0x20, out);
	delete[]textData;
	delete[]dcmpTextData;
	delete[]rodataData;
	delete[]dcmpRodataData;
	delete[]dataData;
	delete[]dcmpDataData;
	return 0;
}

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		printf("nsnsotool\n");
		printf("Compress or decompress NSO/NRO files for Nintendo Switch\n\n");
		printf("Usage:\n");
		printf("nsnsotool <file_name> [out_name]\n");
		return 0;
	}
	FILE* in = fopen(argv[1], "rb");
	if (in == NULL) return -1;
	fseek(in, 0xC, 0);
	u32 flags = 0;
	fread(&flags, 4, 1, in);
	rewind(in);
	FILE* out;
	if (argc == 2)
		out = fopen("temp.bin", "wb");
	else
	{
		out = fopen(argv[2], "wb");
		if (out == NULL) return -1;
	}
	s32 result = -1;
	switch (flags)
	{
	case 0:
		printf("compressing...\n");
		result = compress(in, out);
		break;
	case 0x3F:
		printf("decompressing...\n");
		result = decompress(in, out);
		break;
	default:
		printf("unsupported flags 0x%08X!\n", flags);
	}
	fclose(in);
	fclose(out);
	if (argc == 2 && result == 0)
		fcopy((char*)"temp.bin", argv[1]);
	remove("temp.bin");
	return 0;
}

int fcopy(char* src_name, char* dest_name)
{
	FILE* src = fopen(src_name, "rb");
	if (src == NULL) return -1;
	FILE* dest = fopen(dest_name, "wb");
	fseek(src, 0, 2);
	unsigned int data_size = ftell(src);
	rewind(src);
	unsigned int block_size = 512;
	while (data_size > 0)
	{
		char data[512];
		block_size = 512;
		if (data_size < block_size)
			block_size = data_size;
		data_size -= block_size;
		fread(data, 1, block_size, src);
		fwrite(data, 1, block_size, dest);
	}
	fclose(src);
	fclose(dest);
	return 0;
}

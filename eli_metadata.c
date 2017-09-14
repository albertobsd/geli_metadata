/*
 * Copyright (c) 2017 Luis Alberto Gonzalez <alberto.bsd@gmail.com>
 */
 
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
//#include<stdint.h>
#include<errno.h>

typedef	unsigned int u_int32_t;

#include <sys/endian.h>
#include <sys/md5.h>
#include <sys/types.h>



/*
 From g_eli.h

 * Copyright (c) 2005-2011 Pawel Jakub Dawidek <pawel@dawidek.net>
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define	G_ELI_MAGIC		"GEOM::ELI"
#define	G_ELI_MAXMKEYS		2
#define	G_ELI_MAXKEYLEN		64
#define	G_ELI_DATAKEYLEN	G_ELI_MAXKEYLEN
#define	G_ELI_IVKEYLEN		G_ELI_MAXKEYLEN
#define	SHA512_MDLEN		64

#define	G_ELI_DATAIVKEYLEN	(G_ELI_DATAKEYLEN + G_ELI_IVKEYLEN)

#define	G_ELI_MKEYLEN		(G_ELI_DATAIVKEYLEN + SHA512_MDLEN)
#define	G_ELI_SALTLEN		64

#define	G_ELI_VERSION_00	0
#define	G_ELI_VERSION_01	1
#define	G_ELI_VERSION_02	2
#define	G_ELI_VERSION_03	3
#define	G_ELI_VERSION_04	4
#define	G_ELI_VERSION_05	5
#define	G_ELI_VERSION_06	6
#define	G_ELI_VERSION_07	7
#define	G_ELI_VERSION		G_ELI_VERSION_07


struct g_eli_metadata {
	char		md_magic[16];				/* Magic value. 		16 bytes */		
	uint32_t	md_version;					/* Version number. 		 4 bytes */
	uint32_t	md_flags;					/* Additional flags.     4 bytes */
	uint16_t	md_ealgo;					/* Encryption algorithm. 2 bytes */
	uint16_t	md_keylen;					/* Key length.   		 2 bytes */
	uint16_t	md_aalgo;					/* Authentication algor. 2 bytes */
	uint64_t	md_provsize;				/* Provider's size. 	 8 bytes */
	uint32_t	md_sectorsize;				/* Sector size. 		 4 bytes */
	uint8_t		md_keys;					/* Available keys. 		 1 byte  */

	int32_t		md_iterations;				/* Number o PKCS#5v2.    4 bytes */
	uint8_t		md_salt[G_ELI_SALTLEN]; 	/* Salt. 				64 bytes */
			/* Encrypted master key (IV-key, Data-key, HMAC). */
			
	uint8_t		md_mkeys[G_ELI_MAXMKEYS * G_ELI_MKEYLEN]; /*	   384 bytes */
	u_char		md_hash[16];	/* MD5 hash. 				16 bytes */
} __packed;


int eli_metadata_decode(const u_char *data, struct g_eli_metadata *md);
int eli_metadata_decode_v1v2v3v4v5v6v7(const u_char *data, struct g_eli_metadata *md);
int eli_metadata_decode_v0(const u_char *data, struct g_eli_metadata *md);

/*
	End of g_eli.h
*/


char *hex_buffer = NULL;
char *hex(u_char *ptr, int size);


int main(int argc, char **argv)	{
		if(argc < 2)	{
			printf("Usage\n\t./%s <file>\n",argv[0]);
		}
		else	{
			FILE *f = NULL;
			char *buffer;
			int readed = 0;
			struct g_eli_metadata *md = NULL;
			f = fopen(argv[1],"rb");
			if(f !=  NULL)	{
				buffer = calloc(512,1);
				readed = fread(buffer,1,512,f);
				if(readed == 512)	{
					md = calloc(512,1);
					if(eli_metadata_decode(buffer,md) != EINVAL)	{
					
						printf("Magic: %s\n",md->md_magic);
						printf("Version: %u\n",md->md_version);
						printf("Flags: %u\n",md->md_flags);
						printf("E ALGO: %u\n",md->md_ealgo);
						printf("Key Length: %u\n",md->md_keylen);
						printf("A Algo: %u\n",md->md_aalgo);
						printf("P Size: %llu\n",md->md_provsize);
						printf("Sector Size: %u\n",md->md_sectorsize);
						printf("Avaible Keys: %u\n",md->md_keys);
						printf("Iteraions: %i\n",md->md_iterations);
						printf("Salt: %s\n",hex(md->md_salt,G_ELI_SALTLEN));
						printf("Master Key: %s\n",hex(md->md_mkeys,G_ELI_MAXMKEYS * G_ELI_MKEYLEN));
						printf("MD5: %s\n",hex(md->md_hash,16));
					}
					else	{
						printf("El archivo no es valido");
					}
				}
				else	{
					printf("El archivo esta incompleto\n");
				}
			}
			else	{
				printf("No se puede abrir el archivo\n");
			}
		}		
}

char *hex(u_char *ptr, int size)	{
	char *local_ptr;
	int i = 0;
	if(hex_buffer)	{
		free(hex_buffer);
		hex_buffer = NULL;
	}
	hex_buffer = calloc(size*2+1,1);
	local_ptr = hex_buffer;
	i = 0;
	while(i < size)	{
		sprintf(local_ptr,"%.2X",ptr[i]);
		local_ptr+=2;
		i++;
		
	}
	return hex_buffer;
}

int eli_metadata_decode(const u_char *data, struct g_eli_metadata *md)
{
	int error;
	bcopy(data, md->md_magic, sizeof(md->md_magic));
	if (strcmp(md->md_magic, G_ELI_MAGIC) != 0)
		return (EINVAL);
	md->md_version = le32dec(data + sizeof(md->md_magic));
	switch (md->md_version) {
	case G_ELI_VERSION_00:
		error = eli_metadata_decode_v0(data, md);
		break;
	case G_ELI_VERSION_01:
	case G_ELI_VERSION_02:
	case G_ELI_VERSION_03:
	case G_ELI_VERSION_04:
	case G_ELI_VERSION_05:
	case G_ELI_VERSION_06:
	case G_ELI_VERSION_07:
		error = eli_metadata_decode_v1v2v3v4v5v6v7(data, md);
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}

int eli_metadata_decode_v0(const u_char *data, struct g_eli_metadata *md)
{
	MD5_CTX ctx;
	const u_char *p;
	p = data + sizeof(md->md_magic) + sizeof(md->md_version);
	md->md_flags = le32dec(p);	p += sizeof(md->md_flags);
	md->md_ealgo = le16dec(p);	p += sizeof(md->md_ealgo);
	md->md_keylen = le16dec(p);	p += sizeof(md->md_keylen);
	md->md_provsize = le64dec(p);	p += sizeof(md->md_provsize);
	md->md_sectorsize = le32dec(p);	p += sizeof(md->md_sectorsize);
	md->md_keys = *p;		p += sizeof(md->md_keys);
	md->md_iterations = le32dec(p);	p += sizeof(md->md_iterations);
	bcopy(p, md->md_salt, sizeof(md->md_salt)); p += sizeof(md->md_salt);
	bcopy(p, md->md_mkeys, sizeof(md->md_mkeys)); p += sizeof(md->md_mkeys);
	MD5Init(&ctx);
	MD5Update(&ctx, data, p - data);
	MD5Final(md->md_hash, &ctx);
	if (bcmp(md->md_hash, p, 16) != 0)
		return (EINVAL);
	return (0);
}

int eli_metadata_decode_v1v2v3v4v5v6v7(const u_char *data, struct g_eli_metadata *md)	{
	MD5_CTX ctx;
	const u_char *p;

	p = data + sizeof(md->md_magic) + sizeof(md->md_version);
	md->md_flags = le32dec(p);	p += sizeof(md->md_flags);
	md->md_ealgo = le16dec(p);	p += sizeof(md->md_ealgo);
	md->md_keylen = le16dec(p);	p += sizeof(md->md_keylen);
	md->md_aalgo = le16dec(p);	p += sizeof(md->md_aalgo);
	md->md_provsize = le64dec(p);	p += sizeof(md->md_provsize);
	md->md_sectorsize = le32dec(p);	p += sizeof(md->md_sectorsize);
	md->md_keys = *p;		p += sizeof(md->md_keys);
	md->md_iterations = le32dec(p);	p += sizeof(md->md_iterations);
	bcopy(p, md->md_salt, sizeof(md->md_salt)); p += sizeof(md->md_salt);
	bcopy(p, md->md_mkeys, sizeof(md->md_mkeys)); p += sizeof(md->md_mkeys);
	MD5Init(&ctx);
	MD5Update(&ctx, data, p - data);
	MD5Final(md->md_hash, &ctx);
	if (bcmp(md->md_hash, p, 16) != 0)
		return (EINVAL);
	return (0);
}

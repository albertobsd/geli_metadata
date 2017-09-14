#include<stdio.h>
#include<unistd.h>
#include<stdbool.h>
#include<stdlib.h>
#include<string.h>

#include<errno.h>

typedef	unsigned int u_int32_t;

#include <sys/endian.h>
#include <sys/md5.h>
#include <sys/types.h>
#include <geom/eli/g_eli.h>



unsigned char *odhmac;	/* On-disk HMAC. */
unsigned char enckey[SHA512_MDLEN];	/* Key for encryption. */
unsigned char chmac[SHA512_MDLEN];	/* Calculated HMAC. */
unsigned char hmkey[SHA512_MDLEN];	/* Key for HMAC. */
unsigned char tmpmkey[G_ELI_MKEYLEN];

unsigned long long int Key[8];
static char r[128];

unsigned char random_buffer[1048576];

int increment(unsigned long long int *K, int i);
char *hex_buffer = NULL;
char *hex(unsigned char *buffer,int size);
void reseed_buffer();

int main(int argc, char **argv)	{
	if(argc < 2)	{
		printf("Usage\n\t./%s <file>\n",argv[0]);
	}
	else	{
		bool entrar = true,encontrado = false;
		char *aux_filename;
		FILE *f = NULL,*aux = NULL;
		char *buffer;
		int readed = 0,error;
		struct g_eli_metadata *md = NULL;
		int contador_buffer;
		f = fopen(argv[1],"rb");
		if(f !=  NULL)	{
			buffer = calloc(512,1);
			readed = fread(buffer,1,512,f);
			if(readed == 512)	{
				md = calloc(512,1);
				if(eli_metadata_decode((unsigned char*)buffer,md) != EINVAL)	{
					printf("Magic: %s\n",md->md_magic);
					printf("Version: %u\n",md->md_version);
					printf("Flags: %u\n",md->md_flags);
					printf("E ALGO: %u\n",md->md_ealgo);
					printf("Key Length: %u\n",md->md_keylen);
					printf("A Algo: %u\n",md->md_aalgo);
					printf("P Size: %lu\n",md->md_provsize);
					printf("Sector Size: %u\n",md->md_sectorsize);
					printf("Avaible Keys: %u\n",md->md_keys);
					printf("Iteraions: %i\n",md->md_iterations);
					printf("Salt: %s\n",hex(md->md_salt,G_ELI_SALTLEN));
					printf("Master Key: %s\n",hex(md->md_mkeys,G_ELI_MAXMKEYS * G_ELI_MKEYLEN));
					printf("MD5: %s\n",hex(md->md_hash,16));
					contador_buffer = 0;
					arc4random_buf(random_buffer,1048576);
					aux_filename = calloc(strlen(argv[1 ]) + 10,1);
					sprintf(aux_filename,"%s.aux",argv[1]);
					if(exists(aux_filename))	{
						aux = fopen(aux_filename,"rb");
						if(aux != NULL)	{
							fread(Key,sizeof(unsigned long long int),8,aux);
						}
						else	{
							printf("El archivo existe pero no se puede leer\n");
						}
					}
					else	{
						memset(Key,0,sizeof(Key));
					}
					printf("Iniciando con llave:\n%s\n",hex(Key,G_ELI_USERKEYLEN));
					printf("working...\n");
					do	{						
						//printf("Testing Key\n%s\n",hex((unsigned char*)Key,G_ELI_USERKEYLEN));
						g_eli_crypto_hmac((unsigned char*)Key, G_ELI_USERKEYLEN, "\x01", 1, enckey, 0);
						bcopy(md->md_mkeys, tmpmkey, G_ELI_MKEYLEN);
						error = g_eli_crypto_decrypt(md->md_ealgo, tmpmkey, G_ELI_MKEYLEN, enckey, md->md_keylen);
						if (error != 0) {
							printf("Ocurrio un error en g_eli_crypto_decrypt\n");
							entrar = false;
						}
						else	{
							g_eli_crypto_hmac((unsigned char*)Key, G_ELI_USERKEYLEN, "\x00", 1, hmkey, 0);
							odhmac = tmpmkey + G_ELI_DATAIVKEYLEN;
							g_eli_crypto_hmac(hmkey, sizeof(hmkey), tmpmkey, G_ELI_DATAIVKEYLEN, chmac, 0);
							if(bcmp(odhmac, chmac, SHA512_MDLEN) == 0)	{
								printf("Llave Encontrada:\n%s\n",hex((unsigned char*)Key,G_ELI_USERKEYLEN));
								entrar = false;
							}
						}
						
						/* Inicio de la parte Random esta parte se puede deshabilitar para doblar la velocidad de crackeo
						*/
						//printf("Testing Key\n%s\n",hex((unsigned char*)(random_buffer+contador_buffer),G_ELI_USERKEYLEN));
						g_eli_crypto_hmac((unsigned char*)(random_buffer+contador_buffer), G_ELI_USERKEYLEN, "\x01", 1, enckey, 0);
						bcopy(md->md_mkeys, tmpmkey, G_ELI_MKEYLEN);
						error = g_eli_crypto_decrypt(md->md_ealgo, tmpmkey, G_ELI_MKEYLEN, enckey, md->md_keylen);
						if (error != 0) {
							printf("Ocurrio un error en g_eli_crypto_decrypt\n");
							entrar = false;
						}
						else	{
							g_eli_crypto_hmac((unsigned char*)(random_buffer+contador_buffer), G_ELI_USERKEYLEN, "\x00", 1, hmkey, 0);
							odhmac = tmpmkey + G_ELI_DATAIVKEYLEN;
							g_eli_crypto_hmac(hmkey, sizeof(hmkey), tmpmkey, G_ELI_DATAIVKEYLEN, chmac, 0);
							if(bcmp(odhmac, chmac, SHA512_MDLEN) == 0)	{
								printf("Llave Encontrada:\n%s\n",hex((unsigned char*)(random_buffer+contador_buffer),G_ELI_USERKEYLEN));
								entrar = false;
							}
						}
						/*
						Fin de la parte random
						*/
						contador_buffer++;
						if(contador_buffer == 1048513)	{
							contador_buffer = 0;
							reseed_buffer();							
						}
						if((Key[0] & 0xfffff) == 0xfffff)	{
							printf("Salvando Avance\n");
							aux = fopen(aux_filename,"wb");
							if(aux != NULL){
								fwrite(Key,sizeof(unsigned long long int),8,aux);
								fclose(aux);
							}
							else	{
								printf("No se puede abrir archivo auxiliar\n");
							}
						}
					}while(entrar && !increment(Key,0));
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
	return 0;
}

void reseed_buffer()	{
	//printf("End Buffer: %s \n",hex(random_buffer +1048513,63));
	memcpy(random_buffer,random_buffer +1048513,63);
	arc4random_buf((random_buffer+64),1048513);
	//printf("Begining: %s \n",hex(random_buffer,64));
}

int increment(unsigned long long int *K, int i)	{
	if(K[i]  != 0xffffffffffffffff)	{
		K[i]++;
		return 0;
	}
	else{
		if(i == 7)
			return 1;
		else	{
			K[i] = 0;
			return increment(K,i+1);
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

int exists(const char *fname)
{
	if( access( fname, F_OK ) != -1 ) {
		return 1;
	} else {
		return 0;
	}
}

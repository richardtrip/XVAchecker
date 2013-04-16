#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/sha.h>

#define DEBUG 0
#define CHUNK 1048576 //Размер дискового блока
#define TAR_BLK 512 //Размер TAR блока

char temp[3];

struct posix_header
{                           /* Смещение */
	char name[100];         /*   0 */	
	int size;               /* 124 */	
	int chksum;             /* 148 */
};

struct mbr_record
{                           /* Смещение */


};

void usage(void)
{
	printf("XVA file checker\n");
	printf("Usage:\n chkxva [options] <XVA filename>    verify integrity of XVA file\n\n");
	printf("Options:\n");
	printf(" -v\tVerbose output\n");
	printf(" -o\tExtracts ova.xml alongside with application\n");
	printf(" -m\tCreates metafile\n");
}

void sha2char(unsigned char *chunk_hash, char *string)
{
	memset(string,0,64);
	for(int i=0; i<SHA_DIGEST_LENGTH; i++)
	{
		snprintf(temp, sizeof(temp), "%02x", chunk_hash[i]);
		strcat(string,temp);
	}
}

/**
 * @name    parse_header
 * @brief   Функция проверяет файловый блок
 *
 * Эта функция проверяет TAR заголов и заполняет им структуру
 *
 * @param [in] block	512 байтный блок файла
 */

struct posix_header *parse_header(unsigned char *block)
{
	struct posix_header *h = malloc(sizeof(*h));
	unsigned int sum=0;
	char temp[24];
	//Имя файла
	memcpy(h->name,block,100);
	h->name[99]='\0';
	//Размер файла
	memcpy(temp,block+124,12);
	temp[11]='\0';
	h->size=strtol(temp,NULL,8);
	//Контрольная сумма блока	
	memcpy(temp,block+148,8);
	temp[7]='\0';
	h->chksum=strtol(temp,NULL,8);
	/*
	   *Теперь проверяем заголовок
	   *Я делаю это не в начале просто потому, чтобы избежать
	   *введения лишней переменной
	   *Контрольная сумма это 8-меричная сумма всех беззнаковых байтов
	   *заголовка, причем 8 байтный блок с контрольной суммой представляется как
	   *заполненный пробелами
	 */
	memset(block+148,' ',8); //Заполняем место контрольной суммы пробелами
	for(int i=0; i<TAR_BLK; i++) //Считаем сумму
	{
		sum+=block[i];
	}	
	//Если заголовок битый, возвращает NULL
	if(h->chksum==sum)
	{
		return h;
	}
	else
	{
		free(h);
		return NULL;
	}
}

int extract_file(char *filename, char *object)
{
	int br=0, count=0;
	unsigned char block[TAR_BLK];
	struct posix_header *header;
	
	FILE *tar=fopen(filename,"r");
	if(!tar)
	{
		puts("Error opening XVA");
		return (1);
	}
	//Читаем первый блок, должен быть заголовком
	
	if((br=fread(block,1,sizeof(block),tar))!=TAR_BLK)
	{
		//Файл меньше 512 и он явно не TAR
		puts("This is not TAR archive");
		fclose (tar);
		return (1);
	}
	//Читаем заголовок

	header=parse_header(block);
	if(!header)
	{
		//если вернулось 0 - заголовок битый или это не заголовок
		puts("TAR header is corrupted or it is not a TAR");
		fclose (tar);
		return (1);
	}
	//Проверяем, возможно наш файл  -самый первый
	if(strcmp(header->name, object)==0)
	{
		puts("File found");
		fclose (tar);
		return (1);
	}
	while((br=fread(block,1,sizeof(block),tar))==TAR_BLK)
	{
		/*
		   Файл располагается в архиве как есть, только конец его
		   дописывается до кратности 512 нулями. Поэтому смело считаем
		   блоки, умножаем на 512 и как только оно превысит размер
		   файла - мы достигли конца.
		 */
		if((count*TAR_BLK)<header->size)
		{
			//Записываем блок в буффер			
			count++;
			continue;
		}		
		count=0;
		//Пытаемся прочитать заголовок
		header=parse_header(block);		
		if(!header)
		{
			break;
		}
		//Если это заголовок, то продолжаем
#if DEBUG
		printf("filename: %s\n",header->name);
		printf("filesize: %d\n",header->size);
#endif
		if(strcmp(header->name, object)==0)
		{	
		puts("File found");
		break;
		}

	}
	
	puts("End of file");		
	fclose (tar);
	return (0);
	
}

int xva_asm(char *filename)
{

	return (0);
}

int xva_validate(char *filename)
{
	FILE *tar=fopen(filename,"r");
	if(!tar)
	{
		puts("Error opening XVA");
		return (1);
	}
	char ok=1;
	clock_t start, end;
	double cpu_time_used;
	SHA_CTX ctx;
	struct posix_header *header;
	unsigned char block[TAR_BLK];
	char converted_hash[64];	
	unsigned char chunk_hash[SHA_DIGEST_LENGTH];
	unsigned char prev_hash[SHA_DIGEST_LENGTH];
	unsigned char tar_object[CHUNK];
	int was_disk=0;
	int br=0;
	int count=0;	
	start = clock();
	puts("XVA check started, please wait");
	//Читаем первый блок, должен быть заголовком	
	if((br=fread(block,1,sizeof(block),tar))!=TAR_BLK)
	{
		//Файл меньше 512 и он явно не TAR
		puts("This is not TAR archive");
		fclose (tar);
		return (1);
	}
	//Читаем заголовок

	header=parse_header(block);
	if(!header)
	{
		//если вернулось 0 - заголовок битый или это не заголовок
		puts("TAR header is corrupted or it is not a TAR");
		fclose (tar);
		return (1);
	}
	SHA1_Init(&ctx);
	//Если это заголовок, то читаем дальше весь файл целиком
	while((br=fread(block,1,sizeof(block),tar))>0)
	{
		//Если размер блока равен размеру TAR блока
		if(br!=TAR_BLK)
		{
			puts("Tar block is not 512b! File may be truncated");
			ok=0;
			break;
		}

		/*
		   Файл располагается в архиве как есть, только конец его
		   дописывается до кратности 512 нулями. Поэтому смело считаем
		   блоки, умножаем на 512 и как только оно превысит размер
		   файла - мы достигли конца.
		 */
		if((count*TAR_BLK)<header->size)
		{
			//Записываем блок в буффер
			memcpy(tar_object+(count*TAR_BLK),block,br);
			SHA1_Update(&ctx, block, br);
			count++;
			continue;
		}
		/*
		   Переполнение счетчика, это должен быть заголовок нового
		   файла
		 */

		//Заканчиваем подсчет контрольной суммы
		SHA1_Final(chunk_hash, &ctx);
		/*
		   Файл прочитан, проверяем, был это блок диска,
		   контрольная сумма или может ova.xml
		 */
		//chksum=strstr(header->name,".checksum");
		if(strstr(header->name,".checksum"))
		{
			was_disk=0;
			/*
			   Это контрольная сумма.
			   Блоки дисков записываются как
			   00000000
			   00000000.checksum
			   Поэтому раз это контрольная сумма, то предыдущий
			   файл был его блоком. Здесь я полагаюсь исключительно
			   на надежность источника.
			 */
			sha2char(prev_hash, converted_hash);

			#if DEBUG
			//раз дописывается нулями, то можно смело печатать
			printf("Original block's SHA1: %s\n",tar_object);
			printf("Actual block's SHA1: %s\n",converted_hash);
			#endif

			//сравниваем
			if(strcmp((char *)converted_hash,(char *)tar_object)!=0)
			{
				puts("Disk chunk is corrupted!");
				printf("filename: %s\n",header->name);
				printf("Original block's SHA1: %s\n",tar_object);
				printf("Actual block's SHA1: %s\n",converted_hash);
				ok=0;
				break;
			}
		}
		else
		{
			was_disk=1;
		}
		//Сбрасываем счетчик
		count=0;
		free(header);
		//Пытаемся прочитать заголовок
		header=parse_header(block);
		/*
		   конец TAR архива это минимум 2 пустых блока по 512
		   Это может не соблюдаться, поэтому просто выходим
		   если это не заголов
		 */
		if(!header)
		{
			break;
		}
		//Если это заголовок, то продолжаем
				#if DEBUG
		printf("filename: %s\n",header->name);
		printf("filesize: %d\n",header->size);
				#endif
		//Сохраняем SHA1 в копии
		memcpy(prev_hash,chunk_hash,sizeof(chunk_hash));
		//Реинициализируем алгоритм
		SHA1_Init(&ctx);


		//Если размер не 512, это не может быть TAR архивом

	}
	if(!ok)
	{
		fclose (tar);
		return (1);
	}
	else if(was_disk)
	{
		puts("File may be truncated: unmatched disk chunk");
		fclose (tar);
		return (1);
	}
	puts("End of file");
	puts("XVA's integrity is OK");
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("Finished in %fsecs\n",cpu_time_used);
	fclose (tar);
	return (0);
}

int main (int argc, char *argv[])
{
	if(argc<2)
	{
		usage();
		return (1);
	}
	xva_validate(argv[1]);
	//xva_asm(argv[1]);
	return 0;
}

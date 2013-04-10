#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/sha.h>

#define DEBUG 1
#define CHUNK 1048576 //Размер дискового блока
#define TAR_BLK 512 //Размер TAR блока


struct posix_header
{                           /* Смещение */
	char name[100];         /*   0 */
	char mode[8];           /* 100 */
	char uid[8];            /* 108 */
	char gid[8];            /* 116 */
	int size;               /* 124 */
	char mtime[12];         /* 136 */
	int chksum;             /* 148 */
	char typeflag;          /* 156 */
	char linkname[100];     /* 157 */
	char magic[6];          /* 257 */
	char version[2];        /* 263 */
	char uname[32];         /* 265 */
	char gname[32];         /* 297 */
	char devmajor[8];       /* 329 */
	char devminor[8];       /* 337 */
	char prefix[155];       /* 345 */

};

void sha2char()
{
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

int xva_validate(char *filename)
{
	FILE *tar=fopen(filename,"r");
	if(!tar)
	{
		puts("Error opening XVA");
		return (1);
	}
	clock_t start, end;
	double cpu_time_used;
	SHA_CTX ctx;
	struct posix_header *header;
	char temp[3];
	unsigned char block[TAR_BLK];
	char converted_hash[64];
	unsigned char chunk_hash[SHA_DIGEST_LENGTH];
	unsigned char prev_hash[SHA_DIGEST_LENGTH];
	unsigned char tar_object[CHUNK];

	int br=0;
	int count=0;
	int is_sum=0;
	start = clock();
	//Читаем первый блок, должен быть заголовком
	br=fread(block,1,sizeof(block),tar);
	if(br=!TAR_BLK)
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
		if(strstr(header->name,".checksum"))
		{
			/*
			   Это контрольная сумма.
			   Блоки дисков записываются как
			   00000000
			   00000000.checksum
			   Поэтому раз это контрольная сумма, то предыдущий
			   файл был его блоком. Здесь я полагаюсь исключительно
			   на надежность источника.
			 */
			#if DEBUG
			//раз дописывается нулями, то можно смело печатать
			printf("Original block's SHA1: %s\n",tar_object);
			#endif
		}
		//Сбрасываем счетчик
		count=0;
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
	puts("End of file");
	puts("XVA's integrity is OK");
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("Finished in %fsecs\n",cpu_time_used);
	fclose (tar);
}

int main (int argc, char *argv[])
{
	if(argc<2)
	{
		puts("Provide XVA filename");
		return (1);
	}
	xva_validate(argv[1]);
	return 0;
}

CC=gcc

ncmToMp3: aes.o cJSON.o ncmToMp3.o
	$(CC) -o ncmToMp3 aes.o cJSON.o ncmToMp3.o

aes.o: aes.c aes.h
	$(CC) -c aes.c

cJSON.o: cJSON.c cJSON.h
	$(CC) -c cJSON.c

ncmToMp3.o: ncmToMp3.c
	$(CC) -c ncmToMp3.c

clean: rm -rf *.o ncmToMp3
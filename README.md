## NCM文件转MP3/FLAC
# <font color="#0C8BBA"><center>前言</center></font>
<font color="000000">网易云的Vip音乐下载下来,格式不是mp3/flac这种通用的音乐格式，而是经过加密的ncm文件。只有用网易云的音乐App才能够打开。于是想到可不可以把.ncm文件转换成mp3或者flac文件，上google查了一下，发现有不少人已经做了这件事，但没有发现C语言版本的，就想着写一个纯C语言版本的ncm转mp3/flac。
</font>
# <font color="#oc8bba"><center>NCM文件结构</center></font>
ncm文件的结构，网上有人解析出来了，分为下面几个部分
| 信息| 大小| 说明|
|-------|------|------|
|Magic Header|10 bytes|文件头|
|Key Length|4 bytes|AES128加密后的RC4密钥长度，字节是按小端排序。|
|Key Data|Key Length|用AES128加密后的RC4密钥。<br/>1. 先按字节对0x64进行异或。<br/>2. AES解密,去除填充部分。<br/>3. 去除最前面'neteasecloudmusic'17个字节，得到RC4密钥。|
|Music Info Length|4 bytes|音乐相关信息的长度，小端排序。|
|Music Info Data|Music Info Length|Json格式音乐信息数据。</br>1. 按字节对0x63进行异或。<br/>2. 去除最前面22个字节。<br/>3. Base64进行解码。<br/>4. AES解密。<br/>6. 去除前面6个字节得到Json数据。|
|CRC|4 bytes|跳过|
|Gap|5 bytes|跳过|
|Image Size|4 bytes|图片的大小|
|Image|Image Size|图片数据|
|Music Data| - |1. RC4-KSA生成S盒。<br/>2. 用S盒解密（自定义的解密方法)，不是RC4-PRGA解密。|

两个AES对应密钥
`unsigned char meta_key[] = { 0x23,0x31,0x34,0x6C,0x6A,0x6B,0x5F,0x21,0x5C,0x5D,0x26,0x30,0x55,0x3C,0x27,0x28 };`
`unsigned char core_key[] = { 0x68,0x7A,0x48,0x52,0x41,0x6D,0x73,0x6F,0x35,0x6B,0x49,0x6E,0x62,0x61,0x78,0x57 };`
不得不佩服当初破解这个东西的人，不仅把文件结构摸得请清楚楚，还把密钥也搞到手，应该是个破解大神。有了上面的东西，剩下的就很简单了，按部就班来就行了。
# <font color="#0C8BBA"><center>一些算法准备</center></font>

开始前我们需要把AES算法，BASE64算法,RC4算法和Json解析算法先写好。
除此之外还有一个编码问题，解析出来的ncm文件是用utf-8编码存储的，所以它在中文windows系统下汉字会出现乱码，因为中文windows系统采用的编码是GBK,两者不兼容，所以我们要写一个编码转换算法，将utf8格式字符串转位GBK的。Linux下不用转换，Linux本身就是用UTF-8的。
C语言没有这些库，都要自己来。

- AES用GitHub上的
<a href="https://github.com/kokke/tiny-AES-c">tiny-AES-c</a>
- JSON用GitHub上的CJSON
<a href="https://github.com/DaveGamble/cJSON">cJSON</a>
- Base64和RC4算法比较简单我们自己写
```C
unsigned char* base64_decode(unsigned char* code,int len,int * actLen)
{
    //根据base64表，以字符找到对应的十进制数据  
    int table[] = { 0,0,0,0,0,0,0,0,0,0,0,0,
             0,0,0,0,0,0,0,0,0,0,0,0,
             0,0,0,0,0,0,0,0,0,0,0,0,
             0,0,0,0,0,0,0,62,0,0,0,
             63,52,53,54,55,56,57,58,
             59,60,61,0,0,0,0,0,0,0,0,
             1,2,3,4,5,6,7,8,9,10,11,12,
             13,14,15,16,17,18,19,20,21,
             22,23,24,25,0,0,0,0,0,0,26,
             27,28,29,30,31,32,33,34,35,
             36,37,38,39,40,41,42,43,44,
             45,46,47,48,49,50,51
    };
    long str_len;
    unsigned char* res;
    int i, j;

    //计算解码后的字符串长度  
    //判断编码后的字符串后是否有=
    if (strstr(code, "=="))
        str_len = len / 4 * 3 - 2;
    else if (strstr(code, "="))
        str_len = len / 4 * 3 - 1;
    else
        str_len = len / 4 * 3;

    *actLen = str_len;
    res = malloc(sizeof(unsigned char) * str_len + 1);
    res[str_len] = '\0';

    //以4个字符为一位进行解码  
    for (i = 0, j = 0; i < len - 2; j += 3, i += 4)
    {
        res[j] = ((unsigned char)table[code[i]]) << 2 | (((unsigned char)table[code[i + 1]]) >> 4); 
        res[j + 1] = (((unsigned char)table[code[i + 1]]) << 4) | (((unsigned char)table[code[i + 2]]) >> 2); 
        res[j + 2] = (((unsigned char)table[code[i + 2]]) << 6) | ((unsigned char)table[code[i + 3]]);
    }
    return res;

}
```
- RC4生成S盒
```C
//用key生成S盒
/*
* s: s盒
* key: 密钥
* len: 密钥长度
*/
void rc4Init(unsigned char* s, const unsigned char* key, int len) 
{   
    int i = 0, j = 0;
    unsigned char T[256] = { 0 };
  
    for (i = 0; i < 256; i++)
    {
        s[i] = i;
        T[i] = key[i % len];
    }
  
    for (i = 0; i < 256; i++) 
    {
        j = (j + s[i] + T[i]) % 256;
        unsigned tmp = s[i];
		s[i]=s[j];
		s[j]=tmp;
    }
}
//针对NCM文件的解密
//异或关系
/*
* s: s盒
* data: 要加密或者解密的数据
* len: data的长度
*/
void rc4PRGA(unsigned char* s, unsigned char* data, int len) 
{
    int i = 0;
    int j = 0;
    int k = 0;
    int idx = 0;
    for (idx = 0; idx < len; idx++) 
    {
        i = (idx + 1) % 256;
        j = (i + s[i]) % 256;
        k= (s[i] + s[j]) % 256;
        data[idx]^=s[k];  //异或
    }
}
```
- Windows下utf8转GBK
```C
#ifdef WIN32
#include<Windows.h>
//返回转换好的字符串指针
unsigned char* utf8ToGbk(unsigned char*src,int len)
{
	wchar_t* tmp = (wchar_t*)malloc(sizeof(wchar_t) * len+2);
	unsigned char* newSrc = (unsigned char*)malloc(sizeof(unsigned char) * len + 2);
	
	MultiByteToWideChar(CP_UTF8, 0, src, -1, tmp, len);
	WideCharToMultiByte(CP_ACP, 0, tmp, -1, newSrc, len+2, NULL,NULL);
	return newSrc;
}
#endif
```
# <font color="#oc8bba"><center>完整代码</center></font>

<details>
<summary>点击查看代码</summary>

```
/*
* date:2022-12-12
* author: FL
* purpose: ncm file to mp3
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "aes.h"
#include "cJSON.h"

#ifdef WIN32
#include<Windows.h>
//返回转换好的字符串指针
unsigned char* utf8ToGbk(unsigned char*src,int len)
{
	wchar_t* tmp = (wchar_t*)malloc(sizeof(wchar_t) * len+2);
	unsigned char* newSrc = (unsigned char*)malloc(sizeof(unsigned char) * len + 2);
	
	MultiByteToWideChar(CP_UTF8, 0, src, -1, tmp, len);	//转为unicode
	WideCharToMultiByte(CP_ACP, 0, tmp, -1, newSrc, len+2, NULL,NULL); //转gbk
	
	return newSrc;
}
#endif



void swap(unsigned char* a, unsigned char* b)
{
	unsigned char t = *a;
	*a = *b;
	*b = t;
}

//用key生成S盒
/*
* s: s盒
* key: 密钥
* len: 密钥长度
*/
void rc4Init(unsigned char* s, const unsigned char* key, int len)
{
	int i = 0, j = 0;
	unsigned char T[256] = { 0 };

	for (i = 0; i < 256; i++)
	{
		s[i] = i;
		T[i] = key[i % len];
	}

	for (i = 0; i < 256; i++)
	{
		j = (j + s[i] + T[i]) % 256;
		swap(s + i, s + j);
	}
}
//针对NCM文件的解密
//异或关系
/*
* s: s盒
* data: 要加密或者解密的数据
* len: data的长度
*/
void rc4PRGA(unsigned char* s, unsigned char* data, int len)
{
	int i = 0;
	int j = 0;
	int k = 0;
	int idx = 0;
	for (idx = 0; idx < len; idx++)
	{
		i = (idx + 1) % 256;
		j = (i + s[i]) % 256;
		k = (s[i] + s[j]) % 256;
		data[idx] ^= s[k];  //异或
	}
}

//base64 解码
/*
* code: 要解码的数据
*/
unsigned char* base64_decode(unsigned char* code, int len, int* actLen)
{
	//根据base64表，以字符找到对应的十进制数据  
	int table[] = { 0,0,0,0,0,0,0,0,0,0,0,0,
			 0,0,0,0,0,0,0,0,0,0,0,0,
			 0,0,0,0,0,0,0,0,0,0,0,0,
			 0,0,0,0,0,0,0,62,0,0,0,
			 63,52,53,54,55,56,57,58,
			 59,60,61,0,0,0,0,0,0,0,0,
			 1,2,3,4,5,6,7,8,9,10,11,12,
			 13,14,15,16,17,18,19,20,21,
			 22,23,24,25,0,0,0,0,0,0,26,
			 27,28,29,30,31,32,33,34,35,
			 36,37,38,39,40,41,42,43,44,
			 45,46,47,48,49,50,51
	};
	long str_len;
	unsigned char* res;
	int i, j;

	//计算解码后的字符串长度  
	//判断编码后的字符串后是否有=
	if (strstr(code, "=="))
		str_len = len / 4 * 3 - 2;
	else if (strstr(code, "="))
		str_len = len / 4 * 3 - 1;
	else
		str_len = len / 4 * 3;

	*actLen = str_len;
	res = malloc(sizeof(unsigned char) * str_len + 1);
	res[str_len] = '\0';

	//以4个字符为一位进行解码  
	for (i = 0, j = 0; i < len - 2; j += 3, i += 4)
	{
		res[j] = ((unsigned char)table[code[i]]) << 2 | (((unsigned char)table[code[i + 1]]) >> 4); 
		res[j + 1] = (((unsigned char)table[code[i + 1]]) << 4) | (((unsigned char)table[code[i + 2]]) >> 2);  
		res[j + 2] = (((unsigned char)table[code[i + 2]]) << 6) | ((unsigned char)table[code[i + 3]]); 
	}
	return res;

}
void readFileData(const char* fileName)
{
	FILE* f;
	f = fopen(fileName, "rb");
	if (!f)
	{
		printf("No such file: %s\n", fileName);
		return;
	}
	
	unsigned char buf[16];
	int len=0;
	int i = 0;

	unsigned char meta_key[] = { 0x23,0x31,0x34,0x6C,0x6A,0x6B,0x5F,0x21,0x5C,0x5D,0x26,0x30,0x55,0x3C,0x27,0x28 };
	unsigned char core_key[] = { 0x68,0x7A,0x48,0x52,0x41,0x6D,0x73,0x6F,0x35,0x6B,0x49,0x6E,0x62,0x61,0x78,0x57 };
	
	fseek(f, 10, SEEK_CUR); //f从当前位置移动10个字节
	fread(buf, 1, 4, f);    //读取rc4 key 的长度

	len = (buf[3] << 8 | buf[2]) << 16 | (buf[1] << 8 | buf[0]);
	unsigned char* rc4Key= (unsigned char*)malloc(sizeof(unsigned char) * len);
	fread(rc4Key, 1, len, f);   //读取rc4数据

	//解密rc4密钥
	for (i = 0; i < len; i++)
	{
		rc4Key[i] ^= 0x64;
	}
	
	struct AES_ctx ctx;	
	AES_init_ctx(&ctx, core_key);	//使用core_key密钥
	int packSize = len / 16;	//采用的是AES-ECB加密方式，和Pkcs7padding填充
	for (i = 0; i < packSize; i++)
	{
		AES_ECB_decrypt(&ctx, &rc4Key[i * 16]);
	}
	int pad = rc4Key[len - 1];	//获取填充的长度
	rc4Key[len - pad] = '\0';	//去除填充的部分，得到RC4密钥


	fread(buf, 1, 4, f);    //读取Music Info 长度数据
	len = ((buf[3] << 8 | buf[2]) << 16) | (buf[1] << 8 | buf[0]);
	unsigned char* meta = (unsigned char*)malloc(sizeof(unsigned char) * len);
	fread(meta, 1, len, f); //读取Music Info数据
	//解析Music info信息
	for (i = 0; i < len; i++)
	{
		meta[i] ^= 0x63;
	}
	int act = 0;
	unsigned char* data = base64_decode(&meta[22], len - 22, &act);	//base64解码
	AES_init_ctx(&ctx, meta_key);	//AES解密
	packSize = act / 16;
	for (i = 0; i < packSize; i++)
	{
		AES_ECB_decrypt(&ctx, &data[i * 16]);
	}
	pad = data[act - 1];
	data[act - pad] = '\0';	//去除填充部分
	unsigned char* newData = data;
#ifdef WIN32
	
	newData = utf8ToGbk(data, strlen(data));
	
#endif
	
	cJSON* cjson = cJSON_Parse(&newData[6]);	//json解析，获取格式和名字等
	if (cjson == NULL)
	{
		printf("cjson parse failed\n");
		return;
	}
	//printf("%s\n", cJSON_Print(cjson));	//输出json



	fseek(f, 9, SEEK_CUR);  //从当前位置跳过9个字节
	fread(buf, 1, 4, f);    //读取图片大小
	len = (buf[3] << 8 | buf[2]) << 16 | (buf[1] << 8 | buf[0]);
	unsigned char* img = (unsigned char*)malloc(sizeof(unsigned char) * len);
	fread(img, 1, len, f);  //读取图片数据



	int offset= 1024 * 1024 * 10;    //10MB 音乐数据一般比较大一次读入10MB
	int total = 0;
	int reSize = offset;
	unsigned char* musicData = (unsigned char*)malloc(offset); //10m
	
	while (!feof(f))
	{
		len = fread(musicData+total, 1, offset, f);	//每次读取10M
		total += len;
		reSize += offset;
	    musicData=realloc(musicData,reSize);	//扩容
	}
	
	unsigned char sBox[256] = { 0 };	//s盒
	rc4Init(sBox, &rc4Key[17], strlen(&rc4Key[17]));	//用rC4密钥进行初始化s盒
	rc4PRGA(sBox, musicData, total);	//解密

	//拼接文件名(artist + music name+format)
	char* musicName = cJSON_GetObjectItem(cjson, "musicName")->valuestring;
	cJSON* sub = cJSON_GetObjectItem(cjson, "artist");
	char*artist=cJSON_GetArrayItem(cJSON_GetArrayItem(sub, 0),0)->valuestring;
	char* format = cJSON_GetObjectItem(cjson, "format")->valuestring;
	char* saveFileName =(char*)malloc(strlen(musicName) + strlen(artist) + strlen(format)+5);
	sprintf(saveFileName, "%s - %s.%s", artist, musicName, format);
	FILE* fo=fopen(saveFileName, "wb");
	if (fo == NULL)
	{
		printf("The fileName - '%s' is invalid in this system\n", saveFileName);
	}
	else
	{
		fwrite(musicData, 1, total, fo);
		fclose(fo);
	}
	
	
#ifdef WIN32
	free(newData);
#endif
	free(data);
	free(meta);
	free(img);
	free(musicData);
	fclose(f);
	
}

int main(int argc,char**argv)
{
	readFileData("結束バンド - ギターと孤独と蒼い惑星.ncm");
	return 0;
}
```
</details>

1. AES采用的是AES-ECB模式，pack7padding填充方式。即16个字节为一组，如果不够16个字节，那就缺几个字节就填充几个字节，每个字节的值都是缺少的字节数。所以获取最后一个字节的值就知道要填充了几个字节。
2. RC4解密那里，不是按RC4的来的，虽说叫RC4，但只有生成S盒那里是一样的，其它的不是按RC4算法来的。
3. 有些解析出来音乐的名字，系统是不支持的，比如带'/'的，在创建新文件写入时会失败。
4. 以"結束バンド - ギターと孤独と蒼い惑星.ncm"为例看看它的json数据是怎么样的
> {
        "musicId":      1991012773,
        "musicName":    "ギターと孤独と蒼い惑星",
        "artist":       [["結束バンド", 54103171]],
        "albumId":      153542094,
        "album":        "ギターと孤独と蒼い惑星",
        "albumPicDocId":        "109951167983448236",
        "albumPic":     "https://p4.music.126.net/rfstzrVK05hCPjU-4mzSFA==/109951167983448236.jpg",
        "bitrate":      320000,
        "mp3DocId":     "f481d20151f01d5d681d2768d753ad64",
        "duration":     229015,
        "mvId": 0,
        "alias":        ["TV动画《孤独摇滚！》插曲"],
        "transNames":   [],
        "format":       "mp3",
        "flag": 4
}
>
可以根据需要自由提取需要的信息

# <font color="#oc8bba"><center>星期五女孩</center></font>
![image](https://img2023.cnblogs.com/blog/1330717/202212/1330717-20221216161535136-442362422.png)

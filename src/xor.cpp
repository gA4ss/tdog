#include "xor.h"
#include "stdlib.h"
unsigned Xtrlen(unsigned char* ptr) {
	unsigned ret = 0;
	while (*ptr >= 127) {
		ret++;
		ptr++;
	}
	return ret;
}

unsigned MapAscii(char* str) {
	unsigned len = 0;
	while (*str != 0) {
		*str |= 0x80;
		len++;
		str++;
	}

	return len;
}

void RMapAscii(unsigned char* str, unsigned len) {
	for (unsigned i = 0; i < len; i++) {
		*str &= 0x7F;
		str++;
	}
}

unsigned PolyXorKey(unsigned dwKey) {
	int i = 0, j = 0, n = 0;
	unsigned char* pKey = (unsigned char*)&dwKey;
	unsigned char bVal = 0, bTmp = 0, bTmp2 = 0;
	dwKey ^= 0x5DEECE66DL + 2531011;
	for (i = 0; i < (int)sizeof(unsigned); i++, pKey++) {
		bVal = *pKey;
		/*
		* 第一位与第二位异或放到第一位,依次类推
		* 到达第八位,与第一位异或放到第八位
		* 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01
		*/
		for (j = 0x80, n = 7; j > 0x01; j /= 2, n--) {
			bTmp = (bVal & j) >> n;
			bTmp2 = (bVal & j / 2) >> (n - 1);
			bTmp ^= bTmp2;
			bTmp <<= n;
			bVal |= bTmp;
		}
		bTmp = bVal & 0x01;
		bTmp2 = bVal & 0x80 >> 7;
		bTmp ^= bTmp2;

		*pKey = bVal;
	}/* end for */
	return dwKey;
}

void XorArray(unsigned dwKey, unsigned char* pPoint, 
			  unsigned char* pOut, unsigned iLength) {
	unsigned dwNextKey = dwKey;
	unsigned char* pKey = (unsigned char*)&dwNextKey;
	int i = 0, j = 0;
	for (i = 0; i < (int)iLength; i++) {
		pOut[i] = pPoint[i] ^ pKey[j];
		if (j == (sizeof(unsigned)-1)) {
			// 变换Key
			dwNextKey = PolyXorKey(dwNextKey);
			j = 0;
		} else j++;
	}
}

void XorArray2(unsigned dwKey, unsigned char* pPoint, 
			   unsigned char* pOut, unsigned iLength) {
	if (iLength > 127) return;

	unsigned dwNextKey = dwKey;
	unsigned char* pKey = (unsigned char*)&dwNextKey;
	int i = 0, j = 0;
	for (i = 0; i < (int)iLength; i++) {
		if (pKey[j] >= 127) {
			unsigned char K = pKey[j] ^ (~iLength);
			pOut[i] = pPoint[i] ^ K;
		} else {
			/* 直接XOR上密钥 */
			pOut[i] = pPoint[i] ^ pKey[j];
		}
		/* 每4个字节变换一次 */
		if (j == (sizeof(unsigned)-1)) {
			// 变换Key
			dwNextKey = PolyXorKey(dwNextKey);
			j = 0;
		} else j++;
	}
}

unsigned XEncrypt(unsigned dwKey, unsigned char* pPoint, unsigned char* pOut) {
	unsigned len = MapAscii((char*)pPoint);
	XorArray2(dwKey, pPoint, pOut, len);
	*(pOut + len) = len;
	return len;
}

unsigned XDecrypt(unsigned dwKey, unsigned char* pPoint, unsigned char* pOut) {
	unsigned len = Xtrlen(pPoint);
	XorArray2(dwKey, pPoint, pOut, len);
	RMapAscii(pOut, len);
	*(pOut + len) = '\0';
	return len;
}

void XorCoder(unsigned char* pKey, unsigned char* pBuffer, unsigned iLength) {
	for (int i = 0; i < (int)iLength; i++)
		pBuffer[i] = pBuffer[i] ^ pKey[i];
}

void XorKey32Bits(unsigned dwKeyContext, unsigned char* pKey, 
				  unsigned iKeyLength) {
	int iCount = 0;
	unsigned dwKey = dwKeyContext;
	unsigned char* pOutPut = pKey;
	iCount = (iKeyLength % sizeof(unsigned) != 0) ? iKeyLength / sizeof(unsigned) + 1 : iKeyLength / sizeof(unsigned);

	while (iCount--) {
		dwKey = PolyXorKey(dwKey);
		*(unsigned*)pOutPut ^= dwKey;
		pOutPut += sizeof(unsigned);
	}
}


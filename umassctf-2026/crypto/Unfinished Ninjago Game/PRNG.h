#pragma once
// Mostly taken from here:
// https://prng.di.unimi.it/xoshiro512starstar.c
// Added more jumps functions so that most jumps can be made quickly, the arrays were computed exactly the same way as the original jumps for 2^256 and 2^384
// I only care about outputting a number between a fixed modulus, so the return value of next was slightly modified
// TODO: write short code to compute pow(x, n, char_poly(next)) for arbitrary n instead of relying on multiple fixed jumps, would prolly only need basic polynomial multiplication instead of full FFT nonsense since small number of bits
unsigned long long int s[8];

static void next() {
	const unsigned long long int s1 = s[1] << 11;
	s[2] ^= s[0];
	s[5] ^= s[1];
	s[1] ^= s[2];
	s[7] ^= s[3];
	s[3] ^= s[4];
	s[4] ^= s[5];
	s[0] ^= s[6];
	s[6] ^= s[7];
	s[6] ^= s1;
	s[7] = s[7] << 21 | s[7] >> 43;
}

static void jump0() { next(); }

static void jump16() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0x3d96a5f67b544b01 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xed1329c6a4070e53 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x12990bf72e92851e & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x6d09b79c36d62b2f & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x4190b88dd2af5806 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xde92a62cf9b6e481 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xf07d188da9aded5b & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x1f45f1c244710ce1 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump32() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0x18587e0ed4e7026e & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xcfb2c59a17a592d9 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x937d6ff4e373df9f & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x4cd76c9dcf183c6c & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x371b5582ae2acff1 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xf265c755b171fd8e & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x5c01eaa035e14907 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x4bc4a81d8546c20d & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump48() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0x8958658958ca33f & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xe4c5a8880cf02295 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x55b14f2578556fe5 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x9890b3a1c8935134 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x96c270272cf41807 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x2ead9e6150f7d960 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x97b44ef421417311 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xa48cf07b146bca55 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump64() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0xe7b4e73e78fb8117 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x8391bfebd93542fe & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x60a90a164c9a4cbb & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x7bf9956ec44fed53 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x90ac3bf9614acfab & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xd7c0431b301e1f7a & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x6a330fe287306857 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x87550d2f87fcf1fd & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump80() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0xd05c71bf5ffd1534 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xd22fe5a42481b62e & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xf7d3bf2ba2f22c79 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xc807b587123fb841 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x32de84354ad6c9bc & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x236f99122db9c8de & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x2fd0caf4f1a62820 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xbed6922c2773dfda & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump96() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0xe0824d90a5490508 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x723b4f9544153207 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x75ea598ff8973cf9 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xf0cb913d52eeb61a & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x420368c354e7cac8 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x336db69730b9a17e & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x7fbe82d4470462c4 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xbf45cf4053864168 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump112() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0x169b24003f7292c3 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x414f738ae68a9f4a & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x7bdf255c4f34f1b & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x94d5f5f6fa264104 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xd1a4374e988d117f & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x4be623490982080c & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x4798f17a45140ecb & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x36fa2b6ec1cacd12 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump128() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0xc7ae12ce65328237 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x9d283542f60f82d5 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x970289e59c77718c & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xc8fc2c850773a5df & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x18a3f30ca204b590 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xbedc44bec76af8b5 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x557983fb4641ed85 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xa60ed942c519640 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump144() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0x3cea15cb43aefa36 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x22020191a316000a & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x18c4d44a8797cb39 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x6122bfd9a0a785cb & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x4c7f05b716e5b0c1 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x3e9fad53d0530ac0 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x1079ac5f07dff5f0 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xb95cfb1e2a52d674 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump160() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0x8629d3c5d6551e50 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x5d03e2f0a6b10792 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x4f4a3215c5aefcb0 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xfb7d2409cf4c3a40 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x791a8c2764c9e386 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xbebc0990a0b7460a & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xcb5f001623de86d6 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x8a48ac97c38bf985 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump176() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0xac3ef4491db9b702 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xab8304c0e985d771 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x671fb1fc4fd3da81 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xafa612907027c7c0 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xd3411a1b316b572d & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xa4d797a39551776b & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x67e4ba767df771e3 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x611bceea68b8cd1e & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump192() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0xdb496e81422d1c3 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xe1370b805b2009a0 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x742c230c72b776e9 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x97c12094ff9a5f45 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x17ca9d94fb0e001b & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x185f30cc44e113ef & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xebd44028e8b9e999 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x37d3e61834a52ea2 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump208() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0xe0b829713cf23deb & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xc4356949a2cfd83b & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xfdf11664f39bd49a & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xc2b5421e6b3ebd2e & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x4e4797b898a3d3b0 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x626ccca2199edab & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x2a861861a55c63ce & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x96e59ebb7acda1ae & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump224() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0x5af41fbd515ade8f & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xd9638bfa3fe0691f & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xefb9f85dfc143a3f & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x6779d155151f533a & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x1f96d479dc122662 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x97a611049af72d13 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x744a6fff3a3b4820 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xa184aa3b79af5993 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump240() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0xed13bed2fb3eddac & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x9b9b44cbf76614a0 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xba230e58290f59b2 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x6e430bfc7350d66a & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x4ee0045da1560e11 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xa5b53c715478ed5e & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x58a10b29be1c2449 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x2d6c7aa0c0a99366 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump256() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0x33ed89b6e7a353f9 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x760083d7955323be & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x2837f2fbb5f22fae & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x4b8c5674d309511c & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xb11ac47a7ba28c25 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xf1be7667092bcc1c & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x53851efdb6df0aaf & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x1ebbc8b23eaf25db & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump272() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0xb50f1629425328b5 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xb3e28f1df09693a1 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xd8248055372c51de & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xad730eb31a31a609 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x1afa753e0d0413a7 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x20dbaa97688f9ca9 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xd3017240492a427c & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xe9f9a468de9c2f89 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump288() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0x7d1daa6ee2ebadb6 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x287fb383602eb70d & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x66905c40cc44b83 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x216494af139e9904 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x8d6d7ed8082eb7d4 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x5779be6822895d90 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xa6743c01521e3d40 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x619cd7d6c5269f5f & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump304() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0xeceda37c8801b9d5 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x55d7a5bb4bb5a08d & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x9c801a619e7ce402 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x250722190a2a6eea & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xd224b134d69a1f64 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x648b5535dee537e1 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x2e79d2f16cd1640b & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x630c49df3e41db4e & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump320() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0x7cd739a43307753f & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xef985d8085e83f79 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x5d40b3da06d8c43d & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x1c05fad8cda42c6 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x9d3d80a518fb1c00 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x77d6aa13954aef87 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x51ea18c1c8429006 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x48d0cea9bbce0f6d & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump336() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0x5caa48245a2f43f5 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x538532a2f6902501 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xc45c12d07f79de13 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xfffb3d171015e50c & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x9139536c243747d5 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x1db8779bb59d26be & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x14f6d7673eb70d4e & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x56375088c8287602 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump352() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0x59eda6cec05f85d & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x4c2c027d49680335 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xcab77fc791b25528 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x43bd22ea733667d5 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xd50ec2170882e367 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x3c1643a8607a9567 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xdbb8d29627c4ff68 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xb3a6cf4b19a16195 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump368() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0x209f92f82aae2b2b & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x38f7682590d78c42 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x3f0f7ca6aa72d16e & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x95837ce91ff5d5ee & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x30342a74677609bc & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x2c1920d76bf5dc2e & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xd619493e79da5e4c & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xc73662c92bf90be7 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump384() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0x11467fef8f921d28 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xa2a819f2e79c8ea8 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xa8299fc284b3959a & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xb4d347340ca63ee1 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x1cb0940bedbff6ce & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xd956c5c4fa1f8e17 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x915e38fd4eda93bc & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x5b3ccdfa5d7daca5 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump400() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0xcbcb1ce2f9ed900f & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x9a19b30d6c86b4 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x8ed114c552d7443f & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xfb8c922a34ef014f & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x74ff372663da5327 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xe504f7171144b4b3 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xa207f51dac168f8b & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x61e110fdf65bc9cd & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump416() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0x1d881515c655b44b & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xa67e5a484a024e04 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x62a28b07467aea38 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xe73f7257426fdbf6 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x6313a7f540a3c5ba & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x63beeb8fef52d756 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xafe9c85b5337451b & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xc376c206f6369913 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump432() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0x3d44f46071dcde9f & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x26bbbc2cb5ad3397 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x48eb53308836e739 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x9f0afb1f101d583d & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xe933b386338e6c81 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x4def7d8adedea1a7 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xc2f46d6879ee8e11 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xfa0054daa05bd531 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump448() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0x6ef6eee71fa0848e & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x542c1a94fc3d12b6 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x8aefb26285b6a7ce & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x55048c79feda7401 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x5115d5e1a57feb1e & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xb2a0f741a34abc8f & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x69e6815f5520641c & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xf45915de2f2b79ec & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump464() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0x5e622ae6f1aaebd & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x1f6bbe4ce1b5e32b & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x4958654680afe816 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x2569693ddab27cf4 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xdd12b9a77bf8ef33 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x26b56e1beb2a90ad & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x9e99817fa900580d & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x425acbe1ac2256f & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump480() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0x57f6ca29db34f1f4 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xd8fca164df0c1e9b & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x6f84294e00b66d35 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xeea4145662c7876a & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xa10fc918dcf5ee09 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xd02e3e36e2460115 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xaab23c13d43fb4e5 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x7f506cf199417579 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

static void jump496() {
	unsigned long long int t[8] = {0};
	for (int b = 0; b < 64; b++) {
		if (0xa8ea9a4e883df5c6 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x7426a74e6e34fb0 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xe3372d102776d037 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x416e824af0f05487 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x8550f93157d450af & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xa997a5bda82d8272 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0x8d92ef37e45bffa6 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int b = 0; b < 64; b++) {
		if (0xb706ea9ac253f320 & 1ull << b) for (int w = 0; w < 8; w++) t[w] ^= s[w];
		next();
	}
	for (int w = 0; w < 8; w++) s[w] = t[w];
}

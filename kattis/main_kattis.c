#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define AES_BLOCK_SIZE 16 
#define ROUNDS 10
#define KEY_SIZE 16 

static const uint8_t sbox[16][16] = {
    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
    {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
    {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
};

static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

void print_text_block(const uint8_t iteration, const uint8_t block_index, const char *title, unsigned char *text_block) {
    printf("Iteration %d | Block %d | %s\n", iteration, block_index, title);
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%02X ", text_block[i]); 
        if ((i + 1) % 4 == 0) {
            printf("\n"); 
        }
    }
    printf("\n"); 
}

void key_addition_layer(const uint8_t iteration, const uint8_t block_index, unsigned char *text_block, unsigned char *key) {
    //print_text_block(iteration, block_index, "Before key addition layer: ", text_block); 
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        text_block[i] ^= key[i]; 
    }
    //print_text_block(iteration, block_index, "After key addition layer: ", text_block); 
}; 

void byte_substitution_layer(const uint8_t iteration, const uint8_t block_index, unsigned char *text_block){
    //print_text_block(iteration, block_index, "Before byte substitution layer: ", text_block); 
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        unsigned char byte = text_block[i];
        unsigned char x = (byte >> 4) & 0x0F; 
        unsigned char y = byte & 0x0F;       
        text_block[i] = sbox[x][y];
    }
    //print_text_block(iteration, block_index, "After byte substitution layer: ", text_block); 
}

void shift_rows(const uint8_t iteration, const uint8_t block_index, unsigned char *text_block) {
    unsigned char temp[AES_BLOCK_SIZE];
    //print_text_block(iteration, block_index,  "Before shifting rows: ", text_block); 

    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        temp[i] = text_block[i];
    }

    text_block[0]  = temp[0];    
    text_block[1] = temp[5]; 
    text_block[2] = temp[10]; 
    text_block[3] = temp[15]; 
    text_block[4] = temp[4]; 
    text_block[5] = temp[9]; 
    text_block[6] = temp[14]; 
    text_block[7] = temp[3]; 
    text_block[8] = temp[8]; 
    text_block[9] = temp[13]; 
    text_block[10]  = temp[2]; 
    text_block[11] = temp[7]; 
    text_block[12] = temp[12]; 
    text_block[13] = temp[1]; 
    text_block[14] = temp[6]; 
    text_block[15] = temp[11]; 
    //print_text_block(iteration, block_index, "After shifting rows: ", text_block); 
}

unsigned char gmul(unsigned char a, unsigned char b) {
	unsigned char p = 0;
	while (a && b) {
		if (b & 1)
			p ^= a;

		if (a & 0x80)
			a = (a << 1) ^ 0x11b;
		else
			a <<= 1;
		b >>= 1;
	}
	return p;
}

void mix_columns(const uint8_t iteration, const uint8_t block_index, unsigned char *text_block) {
    //print_text_block(iteration, block_index, "Before mix columns: ", text_block);

    unsigned char temp_state[16];

	temp_state[0] = (unsigned char)(gmul(text_block[0], 2) ^ gmul(text_block[1], 3) ^ text_block[2] ^ text_block[3]);
	temp_state[1] = (unsigned char)(text_block[0] ^ gmul(text_block[1], 2) ^ gmul(text_block[2], 3) ^ text_block[3]);
	temp_state[2] = (unsigned char)(text_block[0] ^ text_block[1] ^ gmul(text_block[2], 2) ^ gmul(text_block[3], 3));
	temp_state[3] = (unsigned char)(gmul(text_block[0], 3) ^ text_block[1] ^ text_block[2] ^ gmul(text_block[3], 2));

	temp_state[4] = (unsigned char)(gmul(text_block[4], 2) ^ gmul(text_block[5], 3) ^ text_block[6] ^ text_block[7]);
	temp_state[5] = (unsigned char)(text_block[4] ^ gmul(text_block[5], 2) ^ gmul(text_block[6], 3) ^ text_block[7]);
	temp_state[6] = (unsigned char)(text_block[4] ^ text_block[5] ^ gmul(text_block[6], 2) ^ gmul(text_block[7], 3));
	temp_state[7] = (unsigned char)(gmul(text_block[4], 3) ^ text_block[5] ^ text_block[6] ^ gmul(text_block[7], 2));

	temp_state[8] = (unsigned char)(gmul(text_block[8], 2) ^ gmul(text_block[9], 3) ^ text_block[10] ^ text_block[11]);
	temp_state[9] = (unsigned char)(text_block[8] ^ gmul(text_block[9], 2) ^ gmul(text_block[10], 3) ^ text_block[11]);
	temp_state[10] = (unsigned char)(text_block[8] ^ text_block[9] ^ gmul(text_block[10], 2) ^ gmul(text_block[11], 3));
	temp_state[11] = (unsigned char)(gmul(text_block[8], 3) ^ text_block[9] ^ text_block[10] ^ gmul(text_block[11], 2));

	temp_state[12] = (unsigned char)(gmul(text_block[12], 2) ^ gmul(text_block[13], 3) ^ text_block[14] ^ text_block[15]);
	temp_state[13] = (unsigned char)(text_block[12] ^ gmul(text_block[13], 2) ^ gmul(text_block[14], 3) ^ text_block[15]);
	temp_state[14] = (unsigned char)(text_block[12] ^ text_block[13] ^ gmul(text_block[14], 2) ^ gmul(text_block[15], 3));
	temp_state[15] = (unsigned char)(gmul(text_block[12], 3) ^ text_block[13] ^ text_block[14] ^ gmul(text_block[15], 2));

	for (int i = 0; i < 16; i++) {
		text_block[i] = temp_state[i];
	}

    //print_text_block(iteration, block_index, "After mix columns: ", text_block);
}

void diffusion_layer(const uint8_t iteration, const uint8_t block_index, unsigned char *text_block){
    shift_rows(iteration, block_index, text_block); 
    mix_columns(iteration, block_index, text_block); 
}

void key_expansion(const unsigned char *key, unsigned char *round_keys) {
    for (int i = 0; i < KEY_SIZE; i++) {
        round_keys[i] = key[i];
    }

    for (int i = KEY_SIZE; i < AES_BLOCK_SIZE * (ROUNDS + 1); i += 4) {
        unsigned char temp[4];
        for (int j = 0; j < 4; j++) {
            temp[j] = round_keys[i - 4 + j];
        }

        if (i % KEY_SIZE == 0) {
            unsigned char t = temp[0];
            temp[0] = sbox[temp[1] >> 4][temp[1] & 0x0F];
            temp[1] = sbox[temp[2] >> 4][temp[2] & 0x0F];
            temp[2] = sbox[temp[3] >> 4][temp[3] & 0x0F];
            temp[3] = sbox[t >> 4][t & 0x0F];
            temp[0] ^= rcon[i / KEY_SIZE];
        }

        for (int j = 0; j < 4; j++) {
            round_keys[i + j] = round_keys[i - KEY_SIZE + j] ^ temp[j];
        }
    }
}

void cipher(unsigned char *key, unsigned char *plaintext, unsigned char *ciphertext, size_t length) {
    unsigned char round_keys[AES_BLOCK_SIZE * (ROUNDS + 1)];
    key_expansion(key, round_keys);

    for (size_t block_index = 0; block_index < length / AES_BLOCK_SIZE; block_index++) {
        unsigned char text_block[AES_BLOCK_SIZE];
        for (int i = 0; i < AES_BLOCK_SIZE; i++) {
            text_block[i] = plaintext[block_index * AES_BLOCK_SIZE + i];
        }

        key_addition_layer(0, block_index, text_block, round_keys);

        for (int round = 1; round <= ROUNDS; round++) {
            byte_substitution_layer(round, block_index, text_block);
            shift_rows(round, block_index, text_block);
            if (round != ROUNDS) {
                mix_columns(round, block_index, text_block);
            }
            key_addition_layer(round, block_index, text_block, round_keys + round * AES_BLOCK_SIZE);
        }

        for (int i = 0; i < AES_BLOCK_SIZE; i++) {
            ciphertext[block_index * AES_BLOCK_SIZE + i] = text_block[i];
        }
    }
}

int main(void) {
    FILE *file = stdin; 
    if (!file) {
        perror("Error opening the file"); 
        return 1;
    }

    fseek(file, 0, SEEK_END); 
    long file_size = ftell(file); 
    rewind(file); 
    
    unsigned char *buffer = (unsigned char *)malloc(file_size); 
    if (!buffer) {
        perror("Memory allocation failed."); 
        fclose(file); 
        return 1; 
    }

    size_t bytes_read = fread(buffer, 1, file_size, file); 
    if (bytes_read != file_size) {
        perror("File read error."); 
        free(buffer); 
        fclose(file); 
        return 1;
    }
    fclose(file); 

    unsigned char key[16];
    for (int i = 0; i < 16; i++) {
        key[i] = buffer[i];
    }
    size_t plaintext_size = file_size - 16;

    unsigned char *plaintext = (unsigned char *)malloc(plaintext_size);
    if (!plaintext) {
        perror("Memory allocation for plaintext failed.");
        free(buffer);
        return 1;
    }

    for (size_t i = 0; i < plaintext_size; i++) {
        plaintext[i] = buffer[16 + i];
    }

    unsigned char *ciphertext = (unsigned char *)malloc(plaintext_size);
    if (!ciphertext) {
        perror("Memory allocation for ciphertext failed.");
        free(buffer);
        free(plaintext);
        return 1;
    }
    cipher(key, plaintext, ciphertext, plaintext_size);

    for (size_t i = 0; i < plaintext_size; i++) {
        printf("%c", ciphertext[i]);
    }
    free(buffer);
    free(plaintext);
    free(ciphertext);

    return 0;
}
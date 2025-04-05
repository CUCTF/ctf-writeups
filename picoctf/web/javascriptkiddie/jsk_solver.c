/*
Written by Madalina Stoicov
March 27, 2025
PicoCTF: Java Script Kiddie
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char **argv)
{
  // Insert the given bytes array as a string
  // This data might differ depending on difference instances of the challenge
  char *bytes_as_string = "156 255 80 255 117 10 239 248 152 253 120 232 36 127 116 255 151 235 25 172 215 0 56 102 219 174 30 15 36 188 93 90 249 36 32 45 123 73 191 151 236 241 151 68 144 250 157 130 1 180 20 85 213 2 157 248 68 255 250 13 60 66 249 82 187 157 29 222 29 30 0 252 126 251 95 0 174 72 194 108 29 101 70 21 121 40 26 132 73 119 254 237 73 192 96 219 137 80 89 71 0 145 1 152 0 69 254 71 0 65 68 35 0 0 119 114 13 222 68 119 1 0 78 40 155 111 95 90 164 0 26 2 0 245 186 0 84 0 0 233 145 46 110 49 48 16 78 223 135 64 197 10 0 120 0 243 252 62 144 188 21 61 1 110 148 208 22 114 160 31 156 17 45 59 72 237 74 218 0 8 32 123 136 65 179 150 32 56 206 43 240 9 156 225 69 54 226 158 106 148 62 48 1 232 173 0 239 248 243 206 82 255 241 252 56 55 152 132 108 181 78 254 175 251 60 183 38 231 63 123 204 48 43 13 131 4 113 75 243 215 32 200 144 195 29 233 196 63 3 190 139 207 89 28 107 159 185 101 59 120 121 12 245 116 64 96 250 187 241 234 231 207 213 239 119 191 233 71 205 127 144 40 251 253 173 186 246 10 227 252 202 242 163 74 237 33 75 49 205 74 154 165 126 231 30 231 232 199 118 65 211 98 204 7 250 244 141 155 243 123 82 137 252 35 183 201 132 91 252 37 244 56 188 86 125 103 216 248 215 146 144 149 21 164 233 219 127 127 207 208 30 154 111 203 63 127 141 231 146 5 20 4 81 239 38 36 19 191 63 61 183 223 215 205 210 239 168 135 148 201 39 248 212 191 160 151 116 19 150 99 249 141 111 188 0 225 193 61 73 140 160 56 23 53 48 5 99 100 175 250 125 151 253 12 150 85 41 72 206 97 52 79 88 196 130 26 157 254 185 181 42 146 217 255 24 125 155 88 111 116 167 62 238 36 52 95 57 54 126 233 184 143 46 183 234 73 183 108 163 228 218 233 129 44 169 191 74 0 30 126 245 10 249 245 241 65 191 245 73 209 50 140 26 72 132 223 181 204 200 123 185 186 183 218 175 228 249 75 180 91 229 252 193 203 187 253 52 166 28 117 119 13 238 134 74 227 127 71 251 237 50 191 61 76 230 90 241 178 221 233 202 254 211 228 156 60 202 241 71 49 24 90 187 3 245 247 159 124 157 250 227 18 150 50 49 101 86 235 162 234 57 124 108 116 245 226 190 28 43 129 220 86 245 85 107 38 215 223 119 242 72 140 213 103 209 194 70 30 96 111 204 128 234 55 184 247 205 49 227 5 220 101 80 171 155 217 87 33 26 173 127 187 128 253 215 111 203 54 210 243 29 237 148 204 235 202 131 191 191 211 157 54 147 104 188 87 4 251 25 17 185 219 247 124 135 228 176 223 135 196 157 130 215 206 124 122 136 248 28 23 175 56 104 209 253 47 161 236 61 252 147 140 86 102 185 82 110 231 91 251 245 216 243 254 236 176 127 134 31 135 152 251 90 0 216 127 102 56 99 56 64 204 61 95";

  int png_bytes[16] = {137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82};

  int i;
  int count = 0;

  // copy of initial string for counting number of bytes
  char *bytes_as_string_counting = strdup(bytes_as_string);

  char *token = strtok(bytes_as_string_counting, " ");

  // count the number of bytes
  for (i = 0; token != NULL; i++)
  {
    count++;
    token = strtok(NULL, " ");
  }

  // official bytes int array with count number of slots
  int bytes[count];

  // make copy for adding numbers to bytes array
  char *bytes_as_string_copy = strdup(bytes_as_string);

  // reassign token
  token = strtok(bytes_as_string_copy, " ");

  // iterate again and add numbers to the bytes array
  for (i = 0; token != NULL; i++)
  {
    bytes[i] = atoi(token);
    token = strtok(NULL, " ");
  }

  // Now for the solving!

  int key[16];
  int shifters[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  int curr_shifter;
  int index;
  int j;

  // for each space in the key array
  for (i = 0; i < 16; i++)
  {

    // for each possible shifter
    for (j = 0; j < sizeof(shifters); j++)
    {
      curr_shifter = shifters[j];

      /*
      Calculate the index of bytes based off the original script
      Original from JS script: bytes[(((j + shifter) * 16) % bytes.length) + i]
      We do not add anything to shifter because we're just iterating through possible shifters
      */
      index = ((curr_shifter * 16) % count) + i;

      // if the bytes in the PNG array match our calculated bytes,
      // add key shifter to our key array
      if (png_bytes[i] == bytes[index])
      {
        key[i] = curr_shifter;
        break;
      }
    }
  }

  // print the key
  for (i = 0; i < 16; i++)
  {
    printf("%d", key[i]);
  }
  printf("\n");
}
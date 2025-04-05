/*
Written by Madalina Stoicov
April 4, 2025
PicoCTF: Java Script Kiddie 2
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char **argv)
{
  // Insert the given bytes array as a string
  // This data might differ depending on difference instances of the challenge
  char *bytes_as_string = "228 80 39 113 0 148 0 143 252 172 225 6 220 243 68 255 63 0 164 243 13 127 26 30 158 48 174 68 6 119 95 128 200 0 191 28 0 107 1 69 243 234 78 13 176 66 110 174 27 16 188 71 135 228 68 235 100 192 219 0 235 72 229 231 56 148 150 114 141 247 101 254 172 69 171 237 90 192 73 117 43 154 78 2 150 254 129 252 124 0 255 71 174 77 152 91 137 13 1 95 69 59 180 0 164 0 78 233 73 171 255 245 0 197 0 0 133 0 243 10 255 120 0 85 0 153 129 195 164 223 70 170 205 10 48 114 73 28 0 243 154 253 15 130 48 32 220 62 37 0 35 65 0 216 156 170 129 59 90 82 112 104 153 12 45 73 221 105 1 147 32 98 68 221 137 108 66 208 191 111 29 45 30 190 84 239 166 159 118 77 151 164 140 250 34 210 24 45 211 223 164 197 74 30 206 132 127 102 111 36 153 144 9 75 10 206 89 102 188 212 103 191 71 20 156 126 73 179 227 131 33 69 226 223 96 88 214 252 91 248 142 219 199 161 196 98 96 0 59 125 205 3 74 206 60 30 69 210 115 144 166 73 249 122 128 229 153 237 231 205 252 122 71 0 143 190 70 255 103 200 65 136 172 166 227 56 55 178 248 255 245 247 24 170 253 165 156 130 31 95 61 57 148 55 159 255 31 96 26 195 185 96 129 252 233 36 36 92 146 111 113 180 242 210 175 208 29 63 102 246 172 154 248 191 12 248 22 153 140 180 61 151 111 0 138 113 101 89 73 125 184 15 12 8 65 144 72 239 249 63 168 110 239 198 158 57 79 235 35 165 197 248 51 223 107 7 132 217 126 255 169 201 223 33 206 181 158 1 166 55 247 219 91 91 14 248 115 149 105 93 117 130 242 84 226 148 83 84 232 117 181 155 51 31 4 180 252 237 161 195 206 164 175 75 19 245 194 65 186 239 62 253 211 111 130 154 24 254 201 214 194 254 105 173 174 5 159 173 8 180 114 23 202 53 39 243 173 87 59 95 61 69 64 219 122 143 62 8 136 51 98 146 128 67 241 126 216 166 166 234 242 191 207 157 242 53 254 39 78 197 215 197 26 33 176 36 193 113 151 211 131 57 158 179 86 113 139 116 59 100 7 189 164 45 200 251 122 12 223 253 179 103 74 228 254 89 155 83 5 173 32 230 126 201 199 199 86 91 126 114 62 105 91 132 183 188 243 193 77 217 243 167 201 190 123 71 196 110 117 115 76 58 103 61 190 114 58 130 232 110 171 147 243 73 157 202 30 235 240 239 174 224 172 149 53 141 170 206 34 55 212 227 229 152 130 217 221 155 221 102 48 87 109 62 235 107 150 58 64 18 142 4 187 24 70 133 180 175 223 13 22 191 126 255 188 198 73 119 40 156 95 111 160 79 155 223 234 138 98 7 145 127 26 141 174 207 179 31 191 122 251 233 191 79 174 130 160 190 232 244 231 191 225 105 222 159 253 46 37 155 3 212 182 239 250 149 102 196 245 107 225 95 126 186 126 233 226 147 189 51 197 30 206 77 239 128 184 176 255 106 236 145 96 160";
  
  /*
  The contents of our array of bytes is similar to JSK1's, except we input zeros in between as fillers
  */
  int png_bytes[32] = {137, 0, 80, 0, 78, 0, 71, 0, 13, 0, 10, 0, 26, 0, 10, 0, 0, 0, 0, 0, 0, 0, 13, 0, 73, 0, 72, 0, 68, 0, 82};

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

  int key[32];
  int shifters[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  int curr_shifter;
  int index;
  int j;

  // for each space in the key array
  for (i = 0; i < 33; i++)
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
      if (png_bytes[i*2] == bytes[index])
      {
        key[i*2] = curr_shifter;
        break;
      }
    }
  }

  // print the key
  for (i = 0; i < 32; i++)
  {
    printf("%d", key[i]);
  }
  printf("\n");
}
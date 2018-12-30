#ifndef __JWT__H
#define __JWT__H

#include <stdint.h>

#define PROJECT_ID "xxxx"
#define RSA_LEN 256

uint8_t jwt_create(char **jwt);

#endif

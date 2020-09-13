#ifdef OC_SECURITY
#include <Arduino.h>
#include <SdFat.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "port/oc_storage.h"
#include "port/oc_log.h"
#define STORE_PATH_SIZE 20
// SD chip select pin
#if defined(SAMD_MKRZERO)
const uint8_t chipSelect = SDCARD_SS_PIN;
#else
const uint8_t chipSelect = 4;
#endif

static SdFat sdfat;
static SdFile sdfile;

static char store_path[STORE_PATH_SIZE];
static int8_t store_path_len;

void list_dir(){
// Initialize at the highest speed supported by the board that is
  // not over 50 MHz. Try a lower speed if SPI errors occur.
  if (!sdfile.open("/", O_RDONLY)) {
    sdfat.errorHalt("open root failed");
  }
  // list all files in the card with date and size
  sdfile.ls();
}

int oc_storage_config(const char *store)
{
  store_path_len = strlen(store);
  if (store_path_len > STORE_PATH_SIZE){
    return -ENOENT;
  }
  strncpy(store_path, store, store_path_len);
  store_path[store_path_len] = '\0';
  /* Initialize at the highest speed supported by the board that is
   not over 50 MHz. Try a lower speed if SPI errors occur.*/
  if (!sdfat.begin(chipSelect)) {
    sdfat.initErrorHalt();
    return -1;
  }
  OC_WRN("initialization done.");
  if( !sdfat.exists(store_path))
  {
    if(!sdfat.mkdir(store_path) )
    {
      OC_ERR("Error creating sec dir");
    }
  }
  list_dir();
  sdfile.close();
  return 0;
}


long
oc_storage_write(const char *store, uint8_t *buf, size_t len)
{
  size_t store_len = strlen(store);
  store_path[store_path_len] = '/';
  strncpy(store_path + store_path_len + 1, store, store_len);
  store_path[1 + store_path_len + store_len] = '\0';
  sdfile.open(store_path, O_WRONLY | O_CREAT | O_TRUNC);
  if(!sdfile.isOpen()) {
    return -1;
  }else {
		if(!(len  =  sdfile.write(buf, len))) {
			OC_ERR("Error writing to: %s",store_path );
			return -1;
		}
		sdfile.close();
  }
  return len;
}

long
oc_storage_read(const char *store, uint8_t *buf, size_t len)
{
  size_t store_len = strlen(store);
  store_path[store_path_len] = '/';
  strncpy(store_path + store_path_len + 1, store, store_len);
  store_path[1 + store_path_len + store_len] = '\0';
  sdfile.open(store_path,  O_RDONLY);
  if(!sdfile.isOpen()) {
    OC_ERR("error opening %s", store_path);
    return -1;
  }
  while(sdfile.available()){
    if(!(len  =  sdfile.read(buf, len))) {
      OC_ERR("Error reading from: %s",store_path );
    }
  }
  sdfile.close();
  return len;
}
#endif /* OC_SECURITY */

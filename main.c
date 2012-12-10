#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <mach-o/dyld.h>
#import <dlfcn.h>
#import <unistd.h>
#import <mach/mach_traps.h>
#import <mach/mach.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <dlfcn.h>

//99.99% of code from Clutch 

#define DYLIB_PATH "@executable_path/crack.dylib"
#define DYLIB_CURRENT_VER 0x10000
#define DYLIB_COMPATIBILITY_VERSION 0x10000


#define swap32(value) (((value & 0xFF000000) >> 24) | ((value & 0x00FF0000) >> 8) | ((value & 0x0000FF00) << 8) | ((value & 0x000000FF) << 24) )
#define ARMV7 9
#define ARMV6 6

void inject_dylib(char* dylib, FILE *file, FILE* newFile, uint32_t top) {
    fseek(file, top, SEEK_SET);
    struct mach_header mach;
    struct load_command l_cmd;
    struct encryption_info_command crypt; // LC_ENCRYPTION_INFO load header (for crypt*)
    struct segment_command __text; // __TEXT segment
    struct dylib_command* load_dylib = NULL;
    
    uint32_t __text_start = 0;
	uint32_t __text_size = 0;
    uint32_t dylib_size = sizeof(DYLIB_PATH) + sizeof(struct dylib_command);
    
    fread(&mach, sizeof(struct mach_header), 1, file);
    for (int lc_index = 0; lc_index < mach.ncmds; lc_index++) { // iterate over each load command
        fread(&l_cmd, sizeof(struct load_command), 1, file);
        printf("load command %c\n", l_cmd.cmd);
        if (l_cmd.cmd == LC_LOAD_DYLIB) {
            printf("found load dylib command!\n");
            fseek(file, -1 * sizeof(struct load_command), SEEK_CUR);
            fread(&load_dylib, sizeof(struct dylib_command), 1, file);
           // char* p = (char *) load_dylib + load_dylib->dylib.name.offset;
            //printf("DYLIB %s \n", p);
            //yolo add some stuff (?)
            printf("found dylib\n");
            //printf("DYLIB %c", load_dylib.dylib.name.offset);
            
        }
        if (l_cmd.cmd == LC_ENCRYPTION_INFO) { // encryption info?
			fseek(file, -1 * sizeof(struct load_command), SEEK_CUR);
			fread(&crypt, sizeof(struct encryption_info_command), 1, file);
            printf("found LC_ENCRYPTION\n");
		}
        else if (l_cmd.cmd == LC_SEGMENT) {
			// some applications, like Skype, have decided to start offsetting the executable image's
			// vm regions by substantial amounts for no apparant reason. this will find the vmaddr of
			// that segment (referenced later during dumping)
			fseek(file, -1 * sizeof(struct load_command), SEEK_CUR);
			fread(&__text, sizeof(struct segment_command), 1, file);
            printf("found LC_SEGMENT\n");
			if (strncmp(__text.segname, "__TEXT", 6) == 0) {
				__text_start = __text.vmaddr;
				__text_size = __text.vmsize;
                printf("found vmaddr\n");
			}
			fseek(file, l_cmd.cmdsize - sizeof(struct segment_command), SEEK_CUR);
		}
       else if (l_cmd.cmd == LC_CODE_SIGNATURE) {
            printf("yolo swag magic!\n");
            //turn you into swag
            
            fseek(file, l_cmd.cmdsize - sizeof(struct load_command), SEEK_CUR); // seek over the load command
        }
        else {
			fseek(file, l_cmd.cmdsize - sizeof(struct load_command), SEEK_CUR); // seek over the load command
		}
    }
    
    printf("zero\n");
    struct dylib_command* command;
    fseek(file, -1 * sizeof(struct load_command), SEEK_CUR);
    fread(&command, sizeof(struct dylib_command), 1, file);
    printf("one\n");
    command->cmd = LC_LOAD_DYLIB;
    printf("twoo\n");
    command->cmdsize = dylib_size;
    command->dylib.compatibility_version = DYLIB_COMPATIBILITY_VERSION;
    command->dylib.current_version = DYLIB_CURRENT_VER;
    command->dylib.timestamp = 2;
    command->dylib.name.offset = sizeof(struct dylib_command);
    //command->dylib.name.ptr = (char *) sizeof(struct dylib_command);
    printf("swag i was\n");
    char *p = (char *) command + command->dylib.name.offset;
    strncpy(p, DYLIB_PATH, sizeof(DYLIB_PATH));
    fseek(file, -1 * sizeof(struct load_command), SEEK_CUR);
    fwrite(command, sizeof(struct dylib_command), 1, file);
    
    struct mach_header* _mach;
    fseek(file, top, SEEK_SET);
    fread(&_mach, sizeof(struct mach_header), 1, file);
    //patch lcmd
    _mach->ncmds += 1;
    _mach->sizeofcmds += dylib_size;
    fseek(file, top, SEEK_SET);
    fwrite(_mach, sizeof(struct mach_header), 1, file);
    printf("OMG YOLO PLS <3\n");
    
}
int main(int argc, const char * argv[])
{

    char binary[4096], dylib[4096], buffer[4096], newfile[4096];

    strlcpy(binary, argv[1], sizeof(binary));
    strlcpy(dylib, argv[2], sizeof(dylib));
    strlcpy(newfile, argv[1], sizeof(newfile));
    strlcat(newfile, ".injected", sizeof(newfile));
    FILE* binaryFile = fopen(binary, "r+");
    FILE *newFile = fopen(newfile, "r+"); 
    fread(&buffer, sizeof(buffer), 1, binaryFile);
    
    struct fat_header* fh = (struct fat_header*) (buffer);
    struct fat_arch* arch = (struct fat_arch*) &fh[1];
    if (fh->magic == FAT_CIGAM) {
        printf("FAT binary! \n");
        int i;
        for (i = 0; i < swap32(fh->nfat_arch); i++) {
            printf("arch %i", swap32(arch->cpusubtype));
            inject_dylib(dylib, binaryFile, newFile, swap32(arch->offset));
            arch++;
        }
    }
    else {
        inject_dylib(dylib, binaryFile, newFile, 0);
    }
    
    // insert code here...
    printf("Hello, World!\n");
    return 0;
}


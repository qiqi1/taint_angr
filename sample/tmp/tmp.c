#include <stdio.h>
#include <string.h>
#include <stdlib.h>


int tmp_cmp(char *str){
    int ret_num=0;
    int i=0;
    int str_len = strlen(str);
    char *new_str = (char*)malloc(str_len + 0x100);
    if(new_str == NULL) return;
    
    memset(new_str,0,str_len+0x100);
    //sprintf(new_str,"%s+%s",str,str);
    strcpy(new_str,str);
    strcat(new_str,str);
    //memcpy(new_str,str,str_len);
   
    for(;i < str_len;i++){
        ret_num += (int)(new_str[i]);
    }
    
    if(strcmp(new_str,str) == 0){
        return 0;
    }
    
   
    return ret_num;
    
}



int main(int argc,char *argv[]){
    
    int num = tmp_cmp(argv[1]);
    printf("num:0x%x\n",num);
    return 0;
}
# -*- coding: UTF-8 -*-

import sys
import os
import re


class TaintHandle():
    def __init__(self,ir_trace):
       
        self.IMark_list = []
        
        self.taint_value = None
        self.taint_mem = None
        
        
        self.static_ir_trace = self.set_ir_trace(ir_trace)
    
    def set_ir_trace(self,ir_trace):
        ret_ir_trace = []
        for i in range(len(ir_trace)):
            for j in range(len(ir_trace[i])):
                ret_ir_trace.append(ir_trace[i][j])
                
        return ret_ir_trace
        
    
    def get_i32(self,dst,src,value_str):
        reg = re.findall('[(](.*?)[)]',src)[0]
        if reg in self.taint_value:
            if dst not in self.taint_value:
                self.taint_value.append(dst)
            return True
        else:
            if dst in self.taint_value:
                self.taint_value.remove(dst)
            return False
    
    def sub_32(self,dst,src,value_str):
        tmpvalues =  re.findall('[(](.*?)[)]',src)[0].split(',')
        value_0 = tmpvalues[0]
        value_1 = tmpvalues[1]
        
        if value_0 in self.taint_value or value_1 in self.taint_value:
            if dst not in self.taint_value:
                self.taint_value.append(dst)
            return True
        else:
            if dst in self.taint_value:
                self.taint_value.remove(dst)
            return False
        
    
    
    def and_32(self,dst,src,value_str):
        tmpvalues =  re.findall('[(](.*?)[)]',src)[0].split(',')
        value_0 = tmpvalues[0]
        value_1 = tmpvalues[1]
        if value_0 in self.taint_value or value_1 in self.taint_value:
            if dst not in self.taint_value:
                self.taint_value.append(dst)
            return True
        else:
            if dst in self.taint_value:
                self.taint_value.remove(dst)
            return False
    
    def put(self,dst,src,value_str):
        reg = re.findall('[(](.*?)[)]',dst)[0]
        if src in self.taint_value:
            if reg not in self.taint_value:
                self.taint_value.append(reg)
            return True 
        else:
            if reg in self.taint_value:
                self.taint_value.remove(reg)
            return False
           
    def stle(self,dst,src,value_str):
        value = re.findall('[(](.*?)[)]',dst)[0]
        addr0 = int(re.findall(value+':<BV\d* (.*?)>',value_str)[0],16)
        addr1 = addr0+1
        addr2 = addr0+2
        addr3 = addr0+3
        if src in self.taint_value:
            if addr0 not in self.taint_mem:
                self.taint_mem.append(addr0)
            if addr1 not in self.taint_mem:
                self.taint_mem.append(addr1)
            if addr2 not in self.taint_mem:
                self.taint_mem.append(addr2)
            if addr3 not in self.taint_mem:
                self.taint_mem.append(addr3)
            
            return True
        
        else:
            if addr0 in self.taint_mem:
                self.taint_mem.remove(addr0)
            if addr1 in self.taint_mem:
                self.taint_mem.remove(addr1)
            if addr2 in self.taint_mem:
                self.taint_mem.remove(addr2)
            if addr3 in self.taint_mem:
                self.taint_mem.remove(addr3)
            return False
    
    def ldle(self,dst,src,value_str):
        addr = []
        if 'LDle:I32' in src:
            value = re.findall('[(](.*?)[)]',src)[0]
            base_addr = None
            if value[0:2] == '0x':
                base_addr = int(value,16)
            else:
                base_addr = int(re.findall(value+':<BV\d* (.*?)>',value_str)[0],16)
            addr.append(base_addr)
            addr.append(base_addr+1)
            addr.append(base_addr+2)
            addr.append(base_addr+3)
        elif 'LDle:I8' in src:
            value = re.findall('[(](.*?)[)]',src)[0]
            base_addr = None
            if value[0:2] == '0x':
                base_addr = int(value,16)
            else:
                base_addr = int(re.findall(value+':<BV\d* (.*?)>',value_str)[0],16) 
            addr.append(base_addr)
        elif "LDle(" in src:
            value = re.findall('[(](.*?)[)]',src)[0]
            base_addr = None
            if value[0:2] == '0x':
                base_addr = int(value,16)
            else:
                base_addr = int(re.findall(value+':<BV\d* (.*?)>',value_str)[0],16)
            
            addr.append(base_addr)
            addr.append(base_addr+1)
            addr.append(base_addr+2)
            addr.append(base_addr+3)
        else:
            raise RuntimeError('ldle error')
        
        
        mem_find = False
        for one_addr in addr:
            if one_addr in self.taint_mem:
                mem_find = True
                break
        
        if mem_find:
            if dst not in self.taint_value:
                self.taint_value.append(dst)
            return True
        else:
            if dst in self.taint_value:
                self.taint_value.remove(dst)
            return False
                
            
        
        
    
    def add32(self,dst,src,value_str):  
        tmpvalues =  re.findall('[(](.*?)[)]',src)[0].split(',')
        value_0 = tmpvalues[0]
        value_1 = tmpvalues[1]
        
        if value_0 in self.taint_value or value_1 in self.taint_value:
            if dst not in self.taint_value:
                self.taint_value.append(dst)
            return True
        else:
            if dst in self.taint_value:
                self.taint_value.remove(dst)
            return False
    
        
        
    def to(self,dst,src,value_str):
        value =  re.findall('[(](.*?)[)]',src)[0].split(',')[0]
        
        if value in self.taint_value:
            if dst not in self.taint_value:
                self.taint_value.append(dst)
            return True
        else:
            if dst in self.taint_value:
                self.taint_value.remove(dst)
            return False
        
    def cmp(self,dst,src,value_str):
        tmpvalues =  re.findall('[(](.*?)[)]',src)[0].split(',')
        value_0 = tmpvalues[0]
        value_1 = tmpvalues[1]
        if value_0 in self.taint_value or value_1 in self.taint_value:
            if dst not in self.taint_value:
                self.taint_value.append(dst)
            return True
        else:
            if dst in self.taint_value:
                self.taint_value.remove(dst)
            return False
    
    
    def ite(self,dst,src,value_str):
        tmpvalues =  re.findall('[(](.*?)[)]',src)[0].split(',')
        value = tmpvalues[0]
        value_0 = tmpvalues[1]
        value_1 = tmpvalues[2]
        num = None
        
        
        if value[0:2] == '0x':
            num = int(value,16)
        else:
            num = int(re.findall(value+':<BV\d* (.*?)>',value_str)[0],16)
            
        if num == 1:
            #value_0
            if value_0 in self.taint_value:
                if dst not in self.taint_value:
                    self.taint_value.append(dst)
                return True
            else:
                if dst in self.taint_value:
                    self.taint_value.remove(dst)
                return False
        else:
            #value_1
            if value_1 in self.taint_value:
                if dst not in self.taint_value:
                    self.taint_value.append(dst)
                return True
            else:
                if dst in self.taint_value:
                    self.taint_value.remove(dst)
                return False
    

    def assignment(self,dst,src,value_str):
        if src in self.taint_value:
            if dst not in self.taint_value:
                self.taint_value.append(dst)
            return True
        else:
            if dst in self.taint_value:
                self.taint_value.remove(dst)
            return False
    
    
    def mul_32(self,dst,src,value_str):
        tmpvalues =  re.findall('[(](.*?)[)]',src)[0].split(',')
        value_0 = tmpvalues[0]
        value_1 = tmpvalues[1]
        if value_0 in self.taint_value or value_1 in self.taint_value:
            if dst not in self.taint_value:
                self.taint_value.append(dst)
            return True
        else:
            if dst in self.taint_value:
                self.taint_value.remove(dst)
            return False
            
            
    def shl_32(self,dst,src,value_str):
        tmpvalues =  re.findall('[(](.*?)[)]',src)[0].split(',')
        value_0 = tmpvalues[0]
        value_1 = tmpvalues[1]
        if value_0 in self.taint_value or value_1 in self.taint_value:
            if dst not in self.taint_value:
                self.taint_value.append(dst)
            return True
        else:
            if dst in self.taint_value:
                self.taint_value.remove(dst)
            return False
            
            
    def or_32(self,dst,src,value_str):
        tmpvalues =  re.findall('[(](.*?)[)]',src)[0].split(',')
        value_0 = tmpvalues[0]
        value_1 = tmpvalues[1]
        if value_0 in self.taint_value or value_1 in self.taint_value:
            if dst not in self.taint_value:
                self.taint_value.append(dst)
            return True
        else:
            if dst in self.taint_value:
                self.taint_value.remove(dst)
            return False
            
    def sar_32(self,dst,src,value_str):
        tmpvalues =  re.findall('[(](.*?)[)]',src)[0].split(',')
        value_0 = tmpvalues[0]
        value_1 = tmpvalues[1]
        if value_0 in self.taint_value or value_1 in self.taint_value:
            if dst not in self.taint_value:
                self.taint_value.append(dst)
            return True
        else:
            if dst in self.taint_value:
                self.taint_value.remove(dst)
            return False
    
    def xor_32(self,dst,src,value_str):
        tmpvalues =  re.findall('[(](.*?)[)]',src)[0].split(',')
        value_0 = tmpvalues[0]
        value_1 = tmpvalues[1]
        if value_0 in self.taint_value or value_1 in self.taint_value:
            if dst not in self.taint_value:
                self.taint_value.append(dst)
            return True
        else:
            if dst in self.taint_value:
                self.taint_value.remove(dst)
            return False
            
            
    def shr_32(self,dst,src,value_str):
        tmpvalues =  re.findall('[(](.*?)[)]',src)[0].split(',')
        value_0 = tmpvalues[0]
        value_1 = tmpvalues[1]
        
        if value_0 in self.taint_value or value_1 in self.taint_value:
            if dst not in self.taint_value:
                self.taint_value.append(dst)
            return True
        else:
            if dst in self.taint_value:
                self.taint_value.remove(dst)
            return False
    #        
    def func_atoi(self,dst,src,value_str):
        tmpvalues =  re.findall('[(](.*?)[)]',src)[0].split(',')
        nptr = tmpvalues[0]
        
        addr_str = re.findall(nptr+':<BV\d* (.*?)>',value_str)[0]
        base_addr = None
        if '0x' in addr_str:
            base_addr = int(addr_str,16)
        else:
            base_addr = int(addr_str)
        
        mem_find = False
        if base_addr in self.taint_mem:
            mem_find = True
        
        reg = re.findall('[(](.*?)[)]',dst)[0]
        
        if mem_find:
            if reg not in self.taint_value:
                self.taint_value.append(reg)
            return True 
        else:
            if reg in self.taint_value:
                self.taint_value.remove(reg)
            return False
    #        
    def func_memcmp(self,dst,src,value_str):
        tmpvalues =  re.findall('[(](.*?)[)]',src)[0].split(',')
        buf1 = tmpvalues[0]
        buf2 = tmpvalues[1]
        count = tmpvalues[2]
        
        buf1_str = re.findall(buf1+':<BV\d* (.*?)>',value_str)[0]
        buf2_str = re.findall(buf2+':<BV\d* (.*?)>',value_str)[0]
        count_str = re.findall(count+':<BV\d* (.*?)>',value_str)[0]
        #
        buf1_value = None
        if '0x' in buf1_str:
            buf1_value = int(buf1_str,16)
        else:
            buf1_value = int(buf1_str)
        # 
        buf2_value = None
        if '0x' in buf2_str:
            buf2_value = int(buf2_str,16)
        else:
            buf2_value = int(buf2_str)
        #
        count_value = None
        if '0x' in count_str:
            count_value = int(count_str,16)
        else:
            count_value = int(count_str)   
        #
        mem_find = False
        for i in range(count_value):
            buf1_addr = buf1_value + i
            buf2_addr = buf2_value + i
            if buf1_addr in self.taint_mem or buf2_addr in self.taint_mem:
                mem_find = True
                break
        
        
        reg = re.findall('[(](.*?)[)]',dst)[0]
        if mem_find:
            if reg not in self.taint_value:
                self.taint_value.append(reg)
            return True 
        else:
            if reg in self.taint_value:
                self.taint_value.remove(reg)
            return False
    #
    #memcpy(void *dest, const void *src, size_t n)    
    def func_memcpy(self,dst,src,value_str):
        tmpvalues =  re.findall('[(](.*?)[)]',src)[0].split(',')
        dest_t = tmpvalues[0]
        src_t = tmpvalues[1]
        n = tmpvalues[2]
        
        dest_str = re.findall(dest_t+':<BV\d* (.*?)>',value_str)[0]
        src_str = re.findall(src_t+':<BV\d* (.*?)>',value_str)[0]
        n_str = re.findall(n+':<BV\d* (.*?)>',value_str)[0]
        #
        dest_value = None
        if '0x' in dest_str:
            dest_value = int(dest_str,16)
        else:
            dest_value = int(dest_str)
        # 
        src_value = None
        if '0x' in src_str:
            src_value = int(src_str,16)
        else:
            src_value = int(src_str)
        #
        n_value = None
        if '0x' in n_str:
            n_value = int(n_str,16)
        else:
            n_value = int(n_str)   
        #
        mem_find = False
        for i in range(n_value):
            dest_addr = dest_value + i
            src_addr = src_value + i
            if src_addr in self.taint_mem:
                if dest_addr not in self.taint_mem:
                    self.taint_mem.append(dest_addr)
                mem_find = True
            else:
                if dest_addr in self.taint_mem:
                    self.taint_mem.remove(dest_addr)
        #
        reg = re.findall('[(](.*?)[)]',dst)[0]
        if reg in self.taint_value:
            self.taint_value.remove(reg)
        #
        if mem_find:
            return True
        else:
            return False
        
    
    #
    #memset(void *s, int ch, size_t n)
    def func_memset(self,dst,src,value_str):
        tmpvalues =  re.findall('[(](.*?)[)]',src)[0].split(',')
        s = tmpvalues[0]
        ch = tmpvalues[1]
        n = tmpvalues[2]
        
        s_str = re.findall(s+':<BV\d* (.*?)>',value_str)[0]
        ch_str = re.findall(ch+':<BV\d* (.*?)>',value_str)[0]
        n_str = re.findall(n+':<BV\d* (.*?)>',value_str)[0]
        #
        s_value = None
        if '0x' in s_str:
            s_value = int(s_str,16)
        else:
            s_value = int(s_str)
        # 
        ch_value = None
        if '0x' in ch_str:
            ch_value = int(ch_str,16)
        else:
            ch_value = int(ch_str)
        #
        n_value = None
        if '0x' in n_str:
            n_value = int(n_str,16)
        else:
            n_value = int(n_str)   
        #
        for i in range(n_value):
            s_addr = s_value + i
            if s_addr in self.taint_mem:
                self.taint_mem.remove(s_addr)
        #
        reg = re.findall('[(](.*?)[)]',dst)[0]
        if reg in self.taint_value:
            self.taint_value.remove(reg)
        
        return False
        
    #
    #int snprintf(char *str, size_t size, const char *format, ...)
    def func_snprintf(self,dst,src,value_str):
        #
        return False
        #
    
    #
    #int sprintf( char *buffer, const char *format, [ argument] … );
    def func_sprintf(self,dst,src,value_str):
        return False
    
    
    #
    #extern char *strcat(char *dest, const char *src);
    def func_strcat(self,dst,src,value_str):
        #get t* value
        tmpvalues =  re.findall('[(](.*?)[)]',src)[0].split(',')
        dest_t = tmpvalues[0]
        src_t = tmpvalues[1]
        #get <BV *> of string
        dest_str = re.findall(dest_t+':<BV\d* (.*?)>',value_str)[0]
        src_str = re.findall(src_t+':<BV\d* (.*?)>',value_str)[0]
        len1_str = re.findall('len1:(.*?);',value_str)[0]
        len2_str = re.findall('len2:(.*?);',value_str)[0]
        
        dest_value = None
        src_value = None
        len1_value = None
        len2_value = None
        
        #str to int
        if '0x' in dest_str:
            dest_value = int(dest_str,16)
        else:
            dest_value = int(dest_str)
            
            
        if '0x' in src_str:
            src_value = int(src_str,16)
        else:
            src_value = int(src_str)
        
        
        #function after,dst len
        len1_value = int(len1_str)
        #src len
        len2_value = int(len2_str)
        #ori dst len
        dest_len = len1_value - len2_value 
        
        
        #
        mem_taint = False
        for i in range(len2_value):
            cur_dest_addr = dest_value + dest_len + i
            cur_src_addr = src_value + i
            
            if cur_src_addr in self.taint_mem:
                if cur_dest_addr not in self.taint_mem:
                    self.taint_mem.append(cur_dest_addr)
                mem_taint = True
            else:
                if cur_dest_addr in self.taint_mem:
                    self.taint_mem.remove(cur_dest_addr)
        
        
        #
        reg = re.findall('[(](.*?)[)]',dst)[0]
        
        if mem_taint:
            if reg not in self.taint_value:
                self.taint_value.append(reg)
        else:
            if reg in self.taint_value:
                self.taint_value.remove(reg)
        
        
        return mem_taint
        
    #
    #char *strchr(const char* _Str,char _Val)
    def func_strchr(self,dst,src,value_str):
        #get t* value
        tmpvalues =  re.findall('[(](.*?)[)]',src)[0].split(',')
        str_t = tmpvalues[0]
        val_t = tmpvalues[1]
        #get <BV *> of string
        str_str = re.findall(str_t+':<BV\d* (.*?)>',value_str)[0]
        len_str = re.findall('len:(.*?);',value_str)[0]
        
        str_value = None
        len_value = None
        
        #str to int
        if '0x' in str_str:
            str_value = int(str_str,16)
        else:
            str_value = int(str_str)
        
        len_value = int(len_str)
        
        #_Val is in taint_value?
        is_taint = False
        if val_t in self.taint_value:
            is_taint = True
        
        #memory _str is in taint_mem?
        for i in range(len_value):
            cur_addr = str_value + i
            if cur_addr in self.taint_mem:
                is_taint = True
                break
        
        #
        reg = re.findall('[(](.*?)[)]',dst)[0]
        
        if is_taint:
            if reg not in self.taint_value:
                self.taint_value.append(reg)
        else:
            if reg in self.taint_value:
                self.taint_value.remove(reg)
        
        
        return is_taint
        
    #
    #extern int strcmp(const char *s1,const char *s2);
    def func_strcmp(self,dst,src,value_str):
        #get t* value
        tmpvalues = re.findall('[(](.*?)[)]',src)[0].split(',')
        s1_t = tmpvalues[0]
        s2_t = tmpvalues[1]
        #get <BV *> of string
        s1_str = re.findall(s1_t+':<BV\d* (.*?)>',value_str)[0]
        s2_str = re.findall(s2_t+':<BV\d* (.*?)>',value_str)[0]
        len1_str = re.findall('len1:(.*?);',value_str)[0]
        len2_str = re.findall('len2:(.*?);',value_str)[0]
        
        s1_value = None
        s2_value = None
        len1_value = None
        len2_value = None
        
        #str to int
        if '0x' in s1_str:
            s1_value = int(s1_str,16)
        else:
            s1_value = int(s1_str)
            
        if '0x' in s2_str:
            s2_value = int(s2_str,16)
        else:
            s2_value = int(s2_str)
            
        len1_value = int(len1_str)
        len2_value = int(len2_str)
        
        #get the min len value
        len_value = None
        if len1_value >= len2_value:
            len_value = len2_value
        else:
            len_value = len1_value
        
        
        mem_taint = False
        #mem s1 is in taint_mem?
        for i in range(len_value):
            cur_addr = s1_value + i
            if cur_addr in self.taint_mem:
                mem_taint = True
                break
        #mem s2 is in taint_mem
        for i in range(len_value):
            cur_addr = s2_value + i
            if cur_addr in self.taint_mem:
                mem_taint = True
                break
        
        #
        reg = re.findall('[(](.*?)[)]',dst)[0]
        
        if mem_taint:
            if reg not in self.taint_value:
                self.taint_value.append(reg)
        else:
            if reg in self.taint_value:
                self.taint_value.remove(reg)
        
        
        return False
    
    #
    #char *strcpy(char* dest, const char *src);
    def func_strcpy(self,dst,src,value_str):
        #get t* value
        tmpvalues = re.findall('[(](.*?)[)]',src)[0].split(',')
        dest_t = tmpvalues[0]
        src_t = tmpvalues[1]
        #get <BV *> of string
        dest_str = re.findall(dest_t+':<BV\d* (.*?)>',value_str)[0]
        src_str = re.findall(src_t+':<BV\d* (.*?)>',value_str)[0]
        len1_str = re.findall('len1:(.*?);',value_str)[0]
        len2_str = re.findall('len2:(.*?);',value_str)[0]
        
        dest_value = None
        src_value = None
        len1_value = None
        len2_value = None
        
        #str to int
        if '0x' in dest_str:
            dest_value = int(dest_str,16)
        else:
            dest_value = int(dest_str)
            
        if '0x' in src_str:
            src_value = int(src_str,16)
        else:
            src_value = int(src_str)
            
        len1_value = int(len1_str)
        len2_value = int(len2_str)
        
        len_value = len1_value
        
        mem_taint = False
        for i in range(len_value):
            cur_dest_addr = dest_value + i
            cur_src_addr = src_value + i
            if cur_src_addr in self.taint_mem:
                if cur_dest_addr not in self.taint_mem:
                    self.taint_mem.append(cur_dest_addr)
                mem_taint = True
            else:
                if cur_dest_addr in self.taint_mem:
                    self.taint_mem.remove(cur_dest_addr)
        
        #
        reg = re.findall('[(](.*?)[)]',dst)[0]
        
        if mem_taint:
            if reg not in self.taint_value:
                self.taint_value.append(reg)
        else:
            if reg in self.taint_value:
                self.taint_value.remove(reg)
        
        return mem_taint
        
        
    #
    #extern unsigned int strlen(char *s);
    def func_strlen(self,dst,src,value_str):
        #get t* value
        tmpvalues = re.findall('[(](.*?)[)]',src)[0].split(',')
        s_t = tmpvalues[0]
        #get <BV *> of string
        s_str = re.findall(s_t+':<BV\d* (.*?)>',value_str)[0]
        len_str = re.findall('len:(.*?);',value_str)[0]
        
        s_value = None
        len_value = None
        
        #str to int
        if '0x' in s_str:
            s_value = int(s_str,16)
        else:
            s_value = int(s_str)
            
        len_value = int(len_str)
        
        mem_taint = False
        for i in range(len_value):
            cur_addr = s_value + i
            if cur_addr in self.taint_mem:
                mem_taint = True
                break
        
        #
        reg = re.findall('[(](.*?)[)]',dst)[0]
        
        if mem_taint:
            if reg not in self.taint_value:
                self.taint_value.append(reg)
        else:
            if reg in self.taint_value:
                self.taint_value.remove(reg)
        
        return mem_taint
        
    #
    #int strncmp ( const char * str1, const char * str2, size_t num );
    def func_strncmp(self,dst,src,value_str):
        #get t* value
        tmpvalues = re.findall('[(](.*?)[)]',src)[0].split(',')
        str1 = tmpvalues[0]
        str2 = tmpvalues[1]
        num = tmpvalues[2]
        #get <BV *> of string
        str1_str = re.findall(str1+':<BV\d* (.*?)>',value_str)[0]
        str2_str = re.findall(str2+':<BV\d* (.*?)>',value_str)[0]
        num_str = re.findall(num+':<BV\d* (.*?)>',value_str)[0]
        
        str1_value = None
        str2_value = None
        num_value = None
        
        
        #str to int
        if '0x' in str1_str:
            str1_value = int(str1_str,16)
        else:
            str1_value = int(str1_str)
            
        if '0x' in str2_str:
            str2_value = int(str2_str,16)
        else:
            str2_value = int(str2_str)
            
        if '0x' in num_str:
            num_value = int(num_str,16)
        else:
            num_value = int(num_str)
            
        mem_taint = False
        
        for i in range(num_value):
            str1_addr = str1_value + i
            str2_addr = str2_value + i
            if str1_addr in self.taint_mem:
                mem_taint = True
                break
            if str2_addr in self.taint_mem:
                mem_taint = True
                break
        
        #
        reg = re.findall('[(](.*?)[)]',dst)[0]
        
        if mem_taint:
            if reg not in self.taint_value:
                self.taint_value.append(reg)
        else:
            if reg in self.taint_value:
                self.taint_value.remove(reg)
            
        return mem_taint
        
        
    #
    #char *strncpy(char *dest,char *src,int size_t n);
    def func_strncpy(self,dst,src,value_str):
        #get t* value
        tmpvalues = re.findall('[(](.*?)[)]',src)[0].split(',')
        dest_t = tmpvalues[0]
        src_t = tmpvalues[1]
        n_t = tmpvalues[2]
        #get <BV *> of string
        dest_str = re.findall(dest_t+':<BV\d* (.*?)>',value_str)[0]
        src_str = re.findall(src_t+':<BV\d* (.*?)>',value_str)[0]
        n_str = re.findall(n_t+':<BV\d* (.*?)>',value_str)[0]
        
        dest_value = None
        src_value = None
        n_value = None
        
        #str to int
        if '0x' in dest_str:
            dest_value = int(dest_str,16)
        else:
            dest_value = int(dest_str)
            
        if '0x' in src_str:
            src_value = int(src_str,16)
        else:
            src_value = int(src_str)
            
        if '0x' in n_str:
            n_value = int(n_str,16)
        else:
            n_value = int(n_str)
        

        #
        mem_taint = False
        for i in range(n_value):
            dst_addr = dest_value + i
            src_addr = src_value + i
            
            if src_addr in self.taint_mem:
                if dst_addr not in self.taint_mem:
                    self.taint_mem.append(dst_addr)
                mem_taint = True
            else:
                if dst_addr in self.taint_mem:
                    self.taint_mem.remove(dst_addr)
        
        
        
        #
        reg = re.findall('[(](.*?)[)]',dst)[0]
        
        if mem_taint:
            if reg not in self.taint_value:
                self.taint_value.append(reg)
        else:
            if reg in self.taint_value:
                self.taint_value.remove(reg)
        
        return mem_taint
        
    #
    #extern char *strstr(char *str1, const char *str2);
    def func_strstr(self,dst,src,value_str):
        #get t* value
        tmpvalues = re.findall('[(](.*?)[)]',src)[0].split(',')
        str1 = tmpvalues[0]
        str2 = tmpvalues[1]
        #get <BV *> of string
        str1_str = re.findall(str1+':<BV\d* (.*?)>',value_str)[0]
        str2_str = re.findall(str2+':<BV\d* (.*?)>',value_str)[0]
        len1_str = re.findall('len1:(.*?);',value_str)[0]
        len2_str = re.findall('len2:(.*?);',value_str)[0]
        
        
        
        str1_value = None
        str2_value = None
        len1_value = None
        len2_value = None
        
        #str to int
        if '0x' in str1_str:
            str1_value = int(str1_str,16)
        else:
            str1_value = int(str1_str)
            
        if '0x' in str2_str:
            str2_value = int(str2_str,16)
        else:
            str2_value = int(str2_str)
        
        len1_value = int(len1_str)
        len2_value = int(len2_str)
        
            
        mem_taint = False
        
        for i in range(len1_value):
            str1_addr = str1_value + i
            if str1_addr in self.taint_mem:
                mem_taint = True
                break
            
        for i in range(len2_value):
            str2_addr = str2_value + i
            if str2_addr in self.taint_mem:
                mem_taint = True
                break
        
        
        #
        reg = re.findall('[(](.*?)[)]',dst)[0]
        
        if mem_taint:
            if reg not in self.taint_value:
                self.taint_value.append(reg)
        else:
            if reg in self.taint_value:
                self.taint_value.remove(reg)
            
        return mem_taint
        
    #
    #long int strtol(const char *nptr,char **endptr,int base);
    def func_strtol(self,dst,src,value_str):
        #get t* value
        tmpvalues = re.findall('[(](.*?)[)]',src)[0].split(',')
        nptr = tmpvalues[0]
        endptr = tmpvalues[1]
        base = tmpvalues[2]
        #get <BV *> of string
        nptr_str = re.findall(nptr+':<BV\d* (.*?)>',value_str)[0]
        
        nptr_value = None
        #string to int
        if '0x' in nptr_str:
            nptr_value = int(nptr_str,16)
        else:
            nptr_value = int(nptr_str)
        
        mem_taint = False
        if base in self.taint_value:
            mem_taint = True
        
        if nptr_value in self.taint_mem:
            mem_taint = True
            
        #
        reg = re.findall('[(](.*?)[)]',dst)[0]
        
        if mem_taint:
            if reg not in self.taint_value:
                self.taint_value.append(reg)
        else:
            if reg in self.taint_value:
                self.taint_value.remove(reg)
            
        return mem_taint
        
    
    #
    #int tolower(int c)
    def func_tolower(self,dst,src,value_str):
        #get t* value
        tmpvalues = re.findall('[(](.*?)[)]',src)[0].split(',')
        c_t = tmpvalues[0]
        
        #
        value_taint = False
        if c_t in self.taint_value:
            value_taint = True
        
        #
        reg = re.findall('[(](.*?)[)]',dst)[0]
        
        if value_taint:
            if reg not in self.taint_value:
                self.taint_value.append(reg)
        else:
            if reg in self.taint_value:
                self.taint_value.remove(reg)
        
        return mem_taint
    
    
    #
    #int toupper(int c)
    def func_toupper(self,dst,src,value_str):
        #get t* value
        tmpvalues = re.findall('[(](.*?)[)]',src)[0].split(',')
        c_t = tmpvalues[0]
        
        #
        value_taint = False
        if c_t in self.taint_value:
            value_taint = True
        
        #
        reg = re.findall('[(](.*?)[)]',dst)[0]
        
        if value_taint:
            if reg not in self.taint_value:
                self.taint_value.append(reg)
        else:
            if reg in self.taint_value:
                self.taint_value.remove(reg)
        
        return mem_taint
        
        
    #
    #other function
    def func_other(self,dst,src,value_str):
        #
        reg = re.findall('[(](.*?)[)]',dst)[0]
        if reg in self.taint_value:
            self.taint_value.remove(reg)
        
        return False
        
    def handle_func(self,dst,src,value_str):
        #
        #import pdb
        #pdb.set_trace()
        #
        
        is_taint = False
        if 'func_atoi(' in src:
            is_taint = self.func_atoi(dst,src,value_str)
        elif 'func_memcmp(' in src:
            is_taint = self.func_memcmp(dst,src,value_str)
        elif 'func_memcpy(' in src:
            is_taint = self.func_memcpy(dst,src,value_str)
        elif 'func_memset(' in src:
            is_taint = self.func_memset(dst,src,value_str)
        elif 'func_snprintf(' in src:
            #modify
            is_taint = self.func_snprintf(dst,src,value_str)
        elif 'func_sprintf(' in src:
            #modify
            is_taint = self.func_sprintf(dst,src,value_str)
        elif 'func_strcat(' in src:
            is_taint = self.func_strcat(dst,src,value_str)
        elif 'func_strchr(' in src:
            is_taint = self.func_strchr(dst,src,value_str)
        elif 'func_strcmp(' in src:
            is_taint = self.func_strcmp(dst,src,value_str)
        elif 'func_strcpy(' in src:
            is_taint = self.func_strcpy(dst,src,value_str)
        elif 'func_strlen(' in src:
            is_taint = self.func_strlen(dst,src,value_str)
        elif 'func_strncmp(' in src:
            is_taint = self.func_strncmp(dst,src,value_str)
        elif 'func_strncpy(' in src:
            is_taint = self.func_strncpy(dst,src,value_str)
        elif 'func_strstr(' in src:
            is_taint = self.func_strstr(dst,src,value_str)
        elif 'func_strtol(' in src:
            is_taint = self.func_strtol(dst,src,value_str)
        elif 'func_tolower(' in src:
            is_taint = self.func_tolower(dst,src,value_str)
        elif 'func_toupper(' in src:
            is_taint = self.func_tolower(dst,src,value_str)
        else:
            is_taint = self.func_other(dst,src,value_str)
        
        
        return is_taint
        
    
    def taint_one_ir(self,ir_str,value_str):
        #
        is_taint = False
        
        ir_list = ir_str.split(' = ')
        dst = ir_list[0]
        src = ir_list[1]
        
        
        
        if 'GET:I' in src:
            is_taint = self.get_i32(dst,src,value_str)
        elif 'Sub32' in src:
            is_taint = self.sub_32(dst,src,value_str)
        elif 'And32' in src:
            is_taint = self.and_32(dst,src,value_str)
        elif 'func_' in src:
            is_taint = self.handle_func(dst,src,value_str)
        elif 'PUT' in dst:
            is_taint = self.put(dst,src,value_str)
        elif 'STle' in dst:
            is_taint = self.stle(dst,src,value_str)
        elif 'LDle' in src:
            is_taint = self.ldle(dst,src,value_str)
        elif 'Add32' in src:
            is_taint = self.add32(dst,src,value_str)
        elif 'to' in src:
            is_taint = self.to(dst,src,value_str)
        elif 'Cmp' in src:
            is_taint = self.cmp(dst,src,value_str)
        elif 'ITE' in src:
            is_taint = self.ite(dst,src,value_str)
        elif len(re.findall('[(](.*?)[)]',src)) == 0:
            is_taint = self.assignment(dst,src,value_str)
        elif 'armg_calculate' in src:
            pass
        elif 'Mul32' in src:
            is_taint = self.mul_32(dst,src,value_str)
        elif 'Shl32' in src:
            is_taint = self.shl_32(dst,src,value_str)
        elif 'Or32' in src:
            is_taint = self.or_32(dst,src,value_str)
        elif 'Sar32' in src:
            is_taint = self.sar_32(dst,src,value_str)
        elif 'Xor32' in src:
            is_taint = self.xor_32(dst,src,value_str)
        elif 'Shr32' in src:
            is_taint = self.shr_32(dst,src,value_str)
        else:
            raise RuntimeError('taint_one_ir error')
        
        return is_taint
        
        
    
    
    def split_one_ir(self,str):
        list_str = str.split('--->')
        ir_str = list_str[0]
        value_str = list_str[1]
        
        if 'if' in ir_str:
            compare_value_str = re.findall('[(](.*?)[)]',ir_str)[0]
            compare_value = int(re.findall(compare_value_str+':<BV1 (\d*)>',value_str)[0])
            if compare_value == 1:
                #1)
                if "Ijk_Boring" in ir_str:
                    ir_str = re.findall('{ (.*); Ijk_Boring }',ir_str)[0]
                elif 'ILGop_Ident' in ir_str:
                    #2)
                    src_ir = re.findall('ILGop_Ident\d*[(](.*)[)]',ir_str)[0]
                    dst_ir = re.findall('(.*?)if',ir_str)[0]
                    ir_str = dst_ir+src_ir
                else:
                    #3)
                    src_ir = re.findall('= (.*)',ir_str)[0]
                    dst_ir = re.findall('[)] (.*?) =',ir_str)[0]
                    ir_str = dst_ir+' = '+src_ir
                    
                
            else:
                #1)
                if "Ijk_Boring" in ir_str:
                    ir_str = ''
                elif 'ILGop_Ident' in ir_str:
                    #2)
                    src_ir = re.findall("else (.*)",ir_str)[0]
                    dst_ir = re.findall('(.*?)if',ir_str)[0]
                    ir_str = dst_ir+src_ir
                else:
                    #3)
                    ir_str = ''
                    
                    
                    
        if ir_str == '':
            return None
        
        is_taint = self.taint_one_ir(ir_str,value_str)
        if is_taint:
            return ir_str
        else:
            return None
            
        

    def split_ir(self):
        one_mark = {}
        dict_mark = None
        
        line_num = 0
        
        for i in range(len(self.static_ir_trace)):
            one_ir_trace = self.static_ir_trace[i]
            
            if 'IMark' in one_ir_trace:
                tmp_mark = one_mark.copy()
                if len(one_mark) != 0 and len(one_mark[dict_mark]) != 0:
                    self.IMark_list.append(tmp_mark)
                one_mark.clear()
                dict_mark = one_ir_trace.split("------ ")[1].split(' ------')[0]
                one_mark[dict_mark] = []
            else:
                one_ir_info = self.split_one_ir(one_ir_trace)
                if one_ir_info != None:
                    if one_ir_info not in one_mark[dict_mark]:
                        list_str = one_ir_trace.split('--->')
                        ir_str = list_str[0]
                        value_str = list_str[1]
                        one_mark[dict_mark].append(ir_str+'--->'+value_str)
            
    
    def taint(self,taint_value,taint_mem):
        self.taint_value = taint_value
        self.taint_mem = taint_mem
        self.split_ir()
#include "openssl/rand.h"
#include "openssl/engine.h"
#include "PKCS11/pkcs11.hpp"

/* Random method */
static RAND_METHOD pkcs_rand =
{
    NULL,
    C_GenerateRandom,
    NULL,
    NULL,
    NULL,
    NULL,
};

/* Engine id */
static const char *engine_pkcs11_id = "ID_PKCS11";

/* Engine name */
static const char *engine_pkcs11_name = "hwTest";

static int pkcs11_init(ENGINE *e)
{
    auto retVal = C_Initialize();
    return retVal;
}

static int pkcs11_destroy(ENGINE *e)
{
    auto retVal = C_Finalize();
    return retVal;
}

static int bind_helper(ENGINE *e)
{
    int ret;
    ret=ENGINE_set_id(e, engine_pkcs11_id);

    ret=ENGINE_set_name(e, engine_pkcs11_name);

    ret=ENGINE_set_RAND(e, &pkcs_rand);
    if(ret!=1)
    {
        printf("ENGINE_set_RAND failed\n");
        return 0;
    }
ret=ENGINE_set_destroy_function(e, hw_destroy);
if(ret!=1)
172
{
printf("ENGINE_set_destroy_function failed\n");
return 0;
}
ret=ENGINE_set_init_function(e, hw_init);
if(ret!=1)
{
printf("ENGINE_set_init_function failed\n");
return 0;
}
ret=ENGINE_set_finish_function(e, hw_finish);
if(ret!=1)
{
printf("ENGINE_set_finish_function failed\n");
return 0;
}
ret=ENGINE_set_ctrl_function(e, hw_ctrl);
if(ret!=1)
{
printf("ENGINE_set_ctrl_function failed\n");
return 0;
}
ret=ENGINE_set_load_privkey_function(e, hw_load_privkey);
if(ret!=1)
{
printf("ENGINE_set_load_privkey_function failed\n");
return 0;
}
ret=ENGINE_set_load_pubkey_function(e, hw_load_pubkey);
if(ret!=1)
{
printf("ENGINE_set_load_pubkey_function failed\n");
return 0;
}
ret=ENGINE_set_cmd_defns(e, hw_cmd_defns);
if(ret!=1)
{
printf("ENGINE_set_cmd_defns failed\n");
return 0;
}
ret=ENGINE_set_ciphers(e,hw_ciphers);
if(ret!=1)
{
printf("ENGINE_set_ciphers failed\n");
173
return 0;
}
ret=ENGINE_set_digests(e,hw_md);
if(ret!=1)
{
printf("ENGINE_set_digests failed\n");
return 0;
}
return 1;
}
static ENGINE *engine_hwcipher(void)
{
ENGINE *ret = ENGINE_new();
if(!ret)
return NULL;
if(!bind_helper(ret))
{
ENGINE_free(ret);
return NULL;
}
return ret;
}
void ENGINE_load_hwcipher()
{
ENGINE *e_hw = engine_hwcipher();
if (!e_hw) return;
ENGINE_add(e_hw);
ENGINE_free(e_hw);
ERR_clear_error();
}
#define HW_set_private_keyID(a) func(e,a,0,(void *)1,NULL)
#include <openssl/engine.h>
#include <openssl/evp.h>
int main()
{
ENGINE *e;
RSA_METHOD *meth;
int ret,num=20,i;
char buf[20],*name;
174
EVP_CIPHER *cipher;
EVP_MD *md;
EVP_MD_CTX mctx,md_ctx;
EVP_CIPHER_CTX ciph_ctx,dciph_ctx;
unsigned char key[8],iv[8];
unsigned char in[50],out[100],dd[60];
int inl,outl,total,dtotal;
RSA *rkey;
RSA_METHOD *rsa_m;
EVP_PKEY *ek,*pkey;
ENGINE_CTRL_FUNC_PTR func;
OpenSSL_add_all_algorithms();
ENGINE_load_hwcipher();
e=ENGINE_by_id("ID_hw");
name = (char *)ENGINE_get_name(e);
printf("engine name :%s \n",name);
/* 随机数生成 */
ret=RAND_set_rand_engine(e);
if(ret!=1)
{
printf("RAND_set_rand_engine err\n");
return -1;
}
ret=ENGINE_set_default_RAND(e);
if(ret!=1)
{
printf("ENGINE_set_default_RAND err\n");
return -1;
}
ret=RAND_bytes((unsigned char *)buf,num);
/* 对称加密 */
for(i=0;i<8;i++)
memset(&key[i],i,1);
EVP_CIPHER_CTX_init(&ciph_ctx);
/* 采用Engine 对称算法 */
cipher=EVP_des_ecb();
ret=EVP_EncryptInit_ex(&ciph_ctx,cipher,e,key,iv);
if(ret!=1)
{
printf("EVP_EncryptInit_ex err\n");
return -1;
}
175
strcpy((char *)in,"zcpsssssssssssss");
inl=strlen((const char *)in);
total=0;
ret=EVP_EncryptUpdate(&ciph_ctx,out,&outl,in,inl);
if(ret!=1)
{
printf("EVP_EncryptUpdate err\n");
return -1;
}
total+=outl;
ret=EVP_EncryptFinal(&ciph_ctx,out+total,&outl);
if(ret!=1)
{
printf("EVP_EncryptFinal err\n");
return -1;
}
total+=outl;
/* 解密 */
dtotal=0;
EVP_CIPHER_CTX_init(&dciph_ctx);
ret=EVP_DecryptInit_ex(&dciph_ctx,cipher,e,key,iv);
if(ret!=1)
{
printf("EVP_DecryptInit_ex err\n");
return -1;
}
ret=EVP_DecryptUpdate(&dciph_ctx,dd,&outl,out,total);
if(ret!=1)
{
printf("EVP_DecryptUpdate err\n");
return -1;
}
dtotal+=outl;
ret=EVP_DecryptFinal(&dciph_ctx,dd+dtotal,&outl);
if(ret!=1)
{
printf("EVP_DecryptFinal err\n");
return -1;
}
dtotal+=outl;
/* Engine 摘要 */
EVP_MD_CTX_init(&mctx);
md=EVP_sha1();
176
ret=EVP_DigestInit_ex(&mctx,md,e);
if(ret!=1)
{
printf("EVP_DigestInit_ex err.\n");
return -1;
}
ret=EVP_DigestUpdate(&mctx,in,inl);
if(ret!=1)
{
printf("EVP_DigestInit_ex err.\n");
return -1;
}
ret=EVP_DigestFinal(&mctx,out,(unsigned int *)&outl);
if(ret!=1)
{
printf("EVP_DigestInit_ex err.\n");
return -1;
}
func=ENGINE_get_ctrl_function(e);
/* 设置计算私钥ID */
HW_set_private_keyID(1);
rkey=RSA_new_method(e);
pkey=EVP_PKEY_new();
EVP_PKEY_set1_RSA(pkey,rkey);
EVP_MD_CTX_init(&md_ctx);
ret=EVP_SignInit_ex(&md_ctx,EVP_sha1(),e);
if(ret!=1)
{
printf("EVP_SignInit_ex err\n");
return -1;
}
ret=EVP_SignUpdate(&md_ctx,in,inl);
if(ret!=1)
{
printf("EVP_SignUpdate err\n");
return -1;
}
ret=EVP_SignFinal(&md_ctx,out,(unsigned int *)&outl,pkey);
if(ret!=1)
{
printf("EVP_SignFinal err\n");
return -1;
}
177
/* 私钥加密 */
RSA_private_encrypt(inl,in,out,rkey,1);
/* 公钥解密 */
/* 公钥加密 */
/* 私钥解密 */
printf("all test ok.\n");
ENGINE_free(e);
ENGINE_finish(e);
return 0;
}
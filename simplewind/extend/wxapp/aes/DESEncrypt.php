<?php
namespace wxapp\aes;
/**
 * Created by PhpStorm.
 * User: 祥贵
 * Date: 2017/12/5
 * Time: 16:54
 */

class DESEncrypt {
    public $ttl;//到期时间 时间格式：20120101(年月日)
    public $key_1;//密钥1
    public $key_2;//密钥2
    public $td;
    public $ks;//密钥的长度
    public $iv;//初始向量
    public $salt;//盐值（某个特定的字符串）
    public $encode;//加密后的信息
    public $return_array = array(); // 返回带有MAC地址的字串数组
    public $mac_addr;//mac地址
    public $filepath;//保存密文的文件路径
    /**
     * 对明文信息进行加密
     * @param $key 密钥
     */
    public function encode($key) {
        $this->td = mcrypt_module_open(MCRYPT_DES,'','ecb',''); //使用MCRYPT_DES算法,ecb模式
        $size=mcrypt_enc_get_iv_size($this->td);//设置初始向量的大小
        $this->iv = mcrypt_create_iv($size, MCRYPT_RAND);//创建初始向量
        $this->ks = mcrypt_enc_get_key_size($this->td);//返回所支持的最大的密钥长度（以字节计算）
        $this->key_1 = substr(md5(md5($key).$this->salt),0,$this->ks);
        mcrypt_generic_init($this->td, $this->key_1, $this->iv); //初始处理
        //要保存到明文
        $con=$this->mac_addr.$this->ttl;
        //加密
        $this->encode = mcrypt_generic($this->td, $con);
        //结束处理
        mcrypt_generic_deinit($this->td);
        //将密文保存到文件中
        $this->savetofile();
    }
    /**
     * 对密文进行解密
     * @param $key 密钥
     */
    public function decode($key) {
        try {
            if (!file_exists($this->filepath)){
                throw new Exception("授权文件不存在");
            }else{//如果授权文件存在的话，则读取授权文件中的密文
                $fp=fopen($this->filepath,'r');
                $secret=fread($fp,filesize($this->filepath));
                $this->key_2 = substr(md5(md5($key).$this->salt),0,$this->ks);
                //初始解密处理
                mcrypt_generic_init($this->td, $this->key_2, $this->iv);
                //解密
                $decrypted = mdecrypt_generic($this->td, $secret);
                //解密后,可能会有后续的\0,需去掉
                $decrypted=trim($decrypted) . "\n";
                //结束
                mcrypt_generic_deinit($this->td);
                mcrypt_module_close($this->td);
                return $decrypted;
            }
        }catch (Exception $e){
            echo $e->getMessage();
        }
    }

}
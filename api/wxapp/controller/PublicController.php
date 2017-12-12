<?php
// +----------------------------------------------------------------------
// | ThinkCMF [ WE CAN DO IT MORE SIMPLE ]
// +----------------------------------------------------------------------
// | Copyright (c) 2013-2017 http://www.thinkcmf.com All rights reserved.
// +----------------------------------------------------------------------
// | Author: Dean <zxxjjforever@163.com>
// +----------------------------------------------------------------------
namespace api\wxapp\controller;

use FontLib\Table\Type\name;
use think\Db;
use cmf\controller\RestBaseController;
use wxapp\aes\WXBizDataCrypt;
use wxapp\aes\DESEncrypt;
use think\Validate;

class PublicController extends RestBaseController
{
    // 微信小程序用户登录 TODO 增加最后登录信息记录,如 ip
    public function login()
    {
        $validate = new Validate([
            'code'           => 'require',
         //   'encrypted_data' => 'require',
         //   'iv'             => 'require',
         //   'raw_data'       => 'require',
         //   'signature'      => 'require',
        ]);

        $validate->message([
            'code.require'           => '缺少参数code!',
            'encrypted_data.require' => '缺少参数encrypted_data!',
            'iv.require'             => '缺少参数iv!',
            'raw_data.require'       => '缺少参数raw_data!',
            'signature.require'      => '缺少参数signature!',
        ]);

        $data = $this->request->param();
        if (!$validate->check($data)) {
            $this->error($validate->getError());
        }

        //TODO 真实逻辑实现
        $code      = $data['code'];
        $appId     = 'wx44647da34cfb3c4f';
        $appSecret = '1095ba66956d1ef906aff3b13a7cb31e';

        $response = cmf_curl_get("https://api.weixin.qq.com/sns/jscode2session?appid=$appId&secret=$appSecret&js_code=$code&grant_type=authorization_code");

        $response = json_decode($response, true);
        if (!empty($response['errcode'])) {
            $this->error('操作失败!');
        }

        $openid     = $response['openid'];
        $sessionKey = $response['session_key'];

        $pc      = new WXBizDataCrypt($appId, $sessionKey);
        $errCode = $pc->decryptData($data['encrypted_data'], $data['iv'], $wxUserData);

        if ($errCode != 0) {
            $this->error('操作失败!');
        }

        $findThirdPartyUser = Db::name("third_party_user")
            ->where('openid', $openid)
            ->where('app_id', $appId)
            ->find();

        $currentTime = time();
        $ip          = $this->request->ip(0, true);

        $wxUserData['sessionKey'] = $sessionKey;
        unset($wxUserData['watermark']);

        if ($findThirdPartyUser) {
            $token = cmf_generate_user_token($findThirdPartyUser['user_id'], 'wxapp');

            $userData = [
                'last_login_ip'   => $ip,
                'last_login_time' => $currentTime,
                'login_times'     => ['exp', 'login_times+1'],
                'more'            => json_encode($wxUserData)
            ];

            if (isset($wxUserData['unionId'])) {
                $userData['union_id'] = $wxUserData['unionId'];
            }

            Db::name("third_party_user")
                ->where('openid', $openid)
                ->where('app_id', $appId)
                ->update($userData);

        } else {

            //TODO 使用事务做用户注册
            $userId = Db::name("user")->insertGetId([
                'create_time'     => $currentTime,
                'user_status'     => 1,
                'user_type'       => 2,
                'sex'             => $wxUserData['gender'],
                'user_nickname'   => $wxUserData['nickName'],
                'avatar'          => $wxUserData['avatarUrl'],
                'last_login_ip'   => $ip,
                'last_login_time' => $currentTime,
            ]);

            Db::name("third_party_user")->insert([
                'openid'          => $openid,
                'user_id'         => $userId,
                'third_party'     => 'wxapp',
                'app_id'          => $appId,
                'last_login_ip'   => $ip,
                'union_id'        => isset($wxUserData['unionId']) ? $wxUserData['unionId'] : '',
                'last_login_time' => $currentTime,
                'create_time'     => $currentTime,
                'login_times'     => 1,
                'status'          => 1,
                'more'            => json_encode($wxUserData)
            ]);

            $token = cmf_generate_user_token($userId, 'wxapp');

        }

        $this->success("登录成功!", ['token' => $token]);


    }


    public function wxlogin()
    {
        $validate = new Validate([
            'code'           => 'require',
            //   'encrypted_data' => 'require',
            //   'iv'             => 'require',
            //   'raw_data'       => 'require',
            //   'signature'      => 'require',
        ]);

        $validate->message([
            'code.require'           => '缺少参数code!',
            'encrypted_data.require' => '缺少参数encrypted_data!',
            'iv.require'             => '缺少参数iv!',
            'raw_data.require'       => '缺少参数raw_data!',
            'signature.require'      => '缺少参数signature!',
        ]);

        $data = $this->request->param();
        if (!$validate->check($data)) {
            $this->error($validate->getError());
        }

        //TODO 真实逻辑实现
        $code      = $data['code'];
        $appId     = 'wx44647da34cfb3c4f';
        $appSecret = '1095ba66956d1ef906aff3b13a7cb31e';

        $response = cmf_curl_get("https://api.weixin.qq.com/sns/jscode2session?appid=$appId&secret=$appSecret&js_code=$code&grant_type=authorization_code");

        $response = json_decode($response, true);
        if (!empty($response['errcode'])) {
            $this->error('操作失败!');
        }

        $openid     = $response['openid'];
        $sessionKey = $response['session_key'];
        echo json_encode($response);
        exit();
    }

    public function version(){

        $version["isshow"] = 0;
        $version["sxf"] = 0.0;
        $version["moren"] = "糍粑鸡蛋我也吃鸡蛋吃吧我也吃";
        $version["url1"] = "https://bsapi.exsde.com";
        $version["url2"] = "https://bsapi.exsde.com";
        $version["qrurl"] = "https://bsapi.exsde.com";
        $version["txsxf"] = 0.02;
        $version["shilieid"] = "723939EE9DCD948F";

        echo json_encode($version);

    }

    public function loginuser(){
        $validate = new Validate([
           // 'code'           => 'require',
               'encryptedData' => 'require',
               'iv'             => 'require',
              'sessionkey'       => 'require',
           //    'signature'      => 'require',
        ]);

        $validate->message([
            'code.require'           => '缺少参数code!',
            'encryptedData.require' => '缺少参数encrypted_data!',
            'iv.require'             => '缺少参数iv!',
            'sessionkey.require'       => '缺少参数sessionkey!',
            'signature.require'      => '缺少参数signature!',
        ]);

        $data = $this->request->param();
        if (!$validate->check($data)) {
            $this->error($validate->getError());
        }

        //TODO 真实逻辑实现

        $appId     = 'wx44647da34cfb3c4f';
        $appSecret = '1095ba66956d1ef906aff3b13a7cb31e';
        $sessionKey = $data['sessionkey'];

        $pc      = new WXBizDataCrypt($appId, $sessionKey);
        $errCode = $pc->decryptData($data['encryptedData'], $data['iv'], $wxUserData);

        if ($errCode != 0) {
            $this->error('操作失败!');
        }

        $openid = $wxUserData['openId'];
        $unionid = $wxUserData['unionId'];
        $des = new \DESEncrypt();
        if ($data['dailiuid'] != "")
        {
            //解密代理

            $dailiuid = $des->decode($data['dailiuid'],'MATICSOFT');
        }
        else
        {
            $dailiuid = "0";
        }
        $code=109;
        $return_code='fail';
        $return_msg='获取失败';

        $findWxappUser = Db::name("wxapp_user")->where(array("unionId"=>$unionid))->find();
        if($findWxappUser){
            $userid = $findWxappUser['userId'];
            if($findWxappUser['laiyuan'] == 1){
                $wxuser_data['laiyuan'] = 2;

                $wxuser_data['nickName'] = $wxUserData['nickName'];
                $wxuser_data['avatarUrl'] = $wxUserData['avatarUrl'];
                $wxuser_data['gender'] = $wxUserData['gender'];
                $wxuser_data['city'] = $wxUserData['city'];
                $wxuser_data['province'] = $wxUserData['province'];
                $wxuser_data['openId'] = $wxUserData['openId'];
                Db::name("wxapp_user")->where(array("unionId"=>$unionid))->update($wxuser_data);

                $findUserinfo = Db::name("wxapp_userinfo")->where(array("userid"=>$userid))->find();
                if($findUserinfo === false || $findUserinfo === null){
                    $userinfo_data['userid'] = $userid;
                    $userinfo_data['tudinum'] = 0;
                    $userinfo_data['tudikouling'] = 0;
                    $userinfo_data['tusunnum'] = 0;
                    $userinfo_data['tusunkouling'] = 0;
                    $userinfo_data['tudisumtc'] = 0;
                    $userinfo_data['tusunsumtc'] = 0;
                    Db::name("wxapp_userinfo")->insert($userinfo_data);
                }
            }

            $code=200;
            $eturn_code='SUCCESS';
            $return_msg='查询成功';
            $isdaili=-1;
            $dailiuid = $userid;
            $nickname = $findWxappUser['nickName'];
            $headurl = $findWxappUser['avatarUrl'];
            $accmoney = $findWxappUser['accmoney'];
        }
        else {
            $query_shifuuid = 0;
            $query_shizuuid = 0;
            $log_data['remarks'] = $dailiuid;
            Db:name("wxapp_logs")->insert($log_data);

            $find_shifu = Db::name("wxapp_user")->where(array("userId"=>$dailiuid))->find();
            if($find_shifu){
                $query_shifuuid = $find_shifu['userId'];
                $query_shizuuid = $find_shifu['shifuuid'];
            }
            $wxuser_data['laiyuan'] = 0;
            $wxuser_data['unionId'] = $unionid;
            $wxuser_data['nickName'] = $wxUserData['nickName'];
            $wxuser_data['avatarUrl'] = $wxUserData['avatarUrl'];
            $wxuser_data['gender'] = $wxUserData['gender'];
            $wxuser_data['city'] = $wxUserData['city'];
            $wxuser_data['province'] = $wxUserData['province'];
            $wxuser_data['ip'] = get_client_ip();
            $wxuser_data['shifuuid'] = $query_shifuuid;
            $wxuser_data['accmoney'] = 0;
            $wxuser_data['ctime'] = date("Y-m-d H:i:s",time());
            $wxuser_data['frozen'] = 0;
            $wxuser_data['shizuuid'] = $query_shizuuid;
            $wxuser_data['tgmoney'] = 0;
            $wxuser_data['openId'] = $wxUserData['openId'];
            Db::name("wxapp_user")->insert($wxuser_data);
            $userid = Db::name("wxapp_user")->getLastInsID();

            $findUserinfo = Db::name("wxapp_userinfo")->where(array("userid"=>$userid))->find();
            if($findUserinfo !== false || $findUserinfo !== null){
                $userinfo_data['userid'] = $userid;
                $userinfo_data['tudinum'] = 0;
                $userinfo_data['tudikouling'] = 0;
                $userinfo_data['tusunnum'] = 0;
                $userinfo_data['tusunkouling'] = 0;
                $userinfo_data['tudisumtc'] = 0;
                $userinfo_data['tusunsumtc'] = 0;
                Db::name("wxapp_userinfo")->insert($userinfo_data);
            }

            if($query_shifuuid>0){
                Db::name("wxapp_userinfo")->setInc("tudinum");
            }
            if($query_shizuuid>0){
                Db::name("wxapp_userinfo")->setInc("tusunnum");
            }

            $code=200;
            $eturn_code='SUCCESS';
            $return_msg='创建成功';
            $isdaili=-1;
            $dailiuid = $userid;
            $nickname = $wxUserData['nickName'];
            $headurl = $wxUserData['avatarUrl'];
            $accmoney = 0;

        }

        if($code == 200){
            $um['userid'] = $des->encode("u".$userid,"MATICSOFT");
            $um['openid'] = $wxUserData['openId'];
            $um['unionid'] = $wxUserData['unionId'];
            $um['nickname'] = $nickname;
            $um['headurl'] = $headurl;
            $um['accmoney'] = $accmoney;
            $um['isdaili'] = $isdaili;
            $um['dailiuid'] = $des->encode($dailiuid);

            $token = cmf_generate_user_token($userid, 'wxapp');

            if($findWxUserTokenAccess = Db::name("wxapp_user_token_access")->where("userid",$userid))
            {
                Db::name("wxapp_user_token_access")->where("userid",$userid)->update(array("token"=>$token));
            }
            else Db::name("wxapp_user_token_access")->insert(array("token"=>$token));
            $return_arr['retcode'] = $return_code;
            $return_arr['retmsg'] = $return_msg;
            $return_arr['user'] = $um;
            $return_arr['token'] = $token;
            echo json_encode($return_arr);
        }

    }

    public function getuserinfo(){
        $validate = new Validate([
            'userid' => 'require',

        ]);

        $validate->message([
            'userid.require'           => '缺少参数userid!',

        ]);

        $data = $this->request->param();
        if (!$validate->check($data)) {
            $this->error($validate->getError());
        }

        $des = new \DESEncrypt();
        if ($data['userid'] != "")
        {
            $userid = $des->decode($data['userid'],'MATICSOFT');
            $userid = str_replace("u","",$userid);
            if($userid>0){
                $findWxuserData = Db::name("wxapp_user")->where("userId",$userid)->find();
                $accmoney = $findWxuserData['accmoney'];
                $response['accmoney'] = $accmoney;
                echo json_encode($response);
            }

        }

    }

}

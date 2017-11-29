<?php
// +----------------------------------------------------------------------
// | ThinkCMF [ WE CAN DO IT MORE SIMPLE ]
// +----------------------------------------------------------------------
// | Copyright (c) 2013-2017 http://www.thinkcmf.com All rights reserved.
// +----------------------------------------------------------------------
// | Author: Dean <zxxjjforever@163.com>
// +----------------------------------------------------------------------
namespace api\home\controller;

use think\Db;
use think\Validate;
use cmf\controller\RestBaseController;

class LoginController extends RestBaseController
{
    // api 首页
    public function index()
    {
        $this->success("恭喜您,API访问成功!", [
            'version' => '1.0.0',
            'doc'     => 'http://www.kancloud.cn/thinkcmf/cmf5api'
        ]);
    }

    public function wxlogin(){
        $wx_config = C('weixin');
        $appid = $wx_config['appid'];
        $secret = $wx_config['secret'];
        $code = trim($_POST['code']);
        if (!$code) {
            echo json_encode(array('status'=>0,'err'=>'非法操作！'));
            exit();
        }
        if (!$appid || !$secret) {
            echo json_encode(array('status'=>0,'err'=>'非法操作！'.__LINE__));
            exit();
        }
        $get_token_url = 'https://api.weixin.qq.com/sns/jscode2session?appid='.$appid.'&secret='.$secret.'&js_code='.$code.'&grant_type=authorization_code';
        $ch = curl_init();
        curl_setopt($ch,CURLOPT_URL,$get_token_url);
        curl_setopt($ch,CURLOPT_HEADER,0);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1 );
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        $res = curl_exec($ch);
        curl_close($ch);
        echo $res;
        exit();
    }

}

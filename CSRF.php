<?php
class CSRF{
    /*
        CSRF ย่อมาจาก Cross-Site Request Forgery เป็นช่องโหว่ที่เกิดขึ้นเมื่อผู้ไม่ประสงค์ดีส่งคำขอ (request) จากเว็บไซต์อื่น (ที่ไม่ได้รับอนุญาต) 
        ไปยังเว็บไซต์ที่ผู้ใช้งานได้เข้าถึงอยู่ โดยใช้ความเชื่อมต่อที่ผู้ใช้งานสามารถเข้าถึงได้เพื่อกระทำการที่ไม่พึงประสงค์ เช่น การเปลี่ยนแปลงข้อมูลส่วนตัว 
        การเพิ่มข้อมูล หรือการกระทำคำสั่งอื่นๆ ที่สามารถทำให้เกิดผลกระทบในระบบของผู้ใช้งานหรือเว็บไซต์นั้นๆ
    */
    private static $_token_name = 'token_key';
    private static $_attribute_name = 'csrf_token';

    public static function hasToken() : bool{
        return isset($_SESSION[self::$_token_name]);
    }

    public static function getToken() : string{
        if(self::hasToken()){
            return $_SESSION[self::$_token_name];
        }
    }

    public static function verificationToken(string $param_token_name = null) : bool{
        if(self::hasToken()){
            return hash_equals(self::getToken(),self::requestToken($param_token_name));
        }
        return false;
    }

    public static function generateToken(int $random_byte = 35) : void{
        if(isset($_SESSION)){
            $_SESSION[self::$_token_name] = bin2hex(random_bytes($random_byte));
        }else{
            session_start();
            $_SESSION[self::$_token_name] = bin2hex(random_bytes($random_byte));
        }
    }

    public static function requestToken(string $param_token_name = null) : string{
        if(isset($_POST[$param_token_name])){
            return $_POST[$param_token_name];
        }
        if(isset($_GET[$param_token_name])){
            return $_GET[$param_token_name];
        }
        if(isset($_SERVER['HTTP_X_CSRF_TOKEN'])){
            return $_SERVER['HTTP_X_CSRF_TOKEN'];
        }
    }

    public static function metaContent(){
        echo '<meta name="'.self::$_attribute_name.'" content="'.self::getToken().'">';
    }
    public static function inputForm(string $method = 'POST'){
        echo '<form method="'.$method.'" action="'.URL_ROOT.'">';
        echo '<input type="hidden" name="'.self::$_attribute_name.'" value="'.self::getToken().'">';
        echo '</form>';
    }
}
?>

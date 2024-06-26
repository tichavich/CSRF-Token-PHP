# CSRF-Token-PHP
cross-site request forgery (CSRF)

## Table of content

1. [CSRF คืออะไร](#CSRF)
2. [ฟังก์ชั่นที่สำคัญ](#function)
3. [วิธีการใช้งาน](#manual-guide)


# CSRF คืออะไร ?
CSRF ย่อมาจาก Cross-Site Request Forgery เป็นช่องโหว่ที่เกิดขึ้นเมื่อผู้ไม่ประสงค์ดีส่งคำขอ (request) จากเว็บไซต์อื่น (ที่ไม่ได้รับอนุญาต) ไปยังเว็บไซต์ที่ผู้ใช้งานได้เข้าถึงอยู่ โดยใช้ความเชื่อมต่อที่ผู้ใช้งานสามารถเข้าถึงได้เพื่อกระทำการที่ไม่พึงประสงค์ เช่น การเปลี่ยนแปลงข้อมูลส่วนตัว การเพิ่มข้อมูล หรือการกระทำคำสั่งอื่นๆ ที่สามารถทำให้เกิดผลกระทบในระบบของผู้ใช้งานหรือเว็บไซต์นั้นๆ

# ฟังก์ชั่นที่สำคัญ
- ฟังก์ชัน hash_equals ใช้สำหรับเปรียบเทียบสตริงของค่าแฮชแบบแข็งแรง (hash) แบบคงเดิม (constant-time comparison) โดยไม่สนใจความยาวของสตริง และมีการป้องกันการโจมตีแบบแฝงข้อความ (timing attacks) ซึ่งเป็นวิธีการโจมตีที่ใช้เวลาเพิ่มเติมในการประมวลผลเมื่อเปรียบเทียบสตริง
- ฟังก์ชัน bin2hex ใช้สำหรับแปลงข้อมูลในรูปแบบ binary เป็นข้อความฐานสิบหก (hexadecimal) ซึ่งมักจะใช้ในการเข้ารหัสข้อมูลเช่นในการเข้ารหัสข้อมูลไบนารีเป็นข้อความที่อ่านได้ หรือการเข้ารหัสข้อมูลในรูปแบบที่ไม่มีอักขระพิเศษใน URL ด้วยเอง เป็นต้น
- ฟังก์ชัน random_bytes(): ใช้สร้างข้อมูลสุ่มโดยใช้เครื่องมือสุ่มในระบบปฏิบัติการ (operating system's CSPRNG - Cryptographically Secure Pseudo-Random Number Generator) ที่มีความปลอดภัยสูง ข้อมูลที่สร้างขึ้นมาจะเป็นข้อมูลที่สุ่มจริงที่มีความเสมือนจริงและปลอดภัยในการใช้งาน.

# วิธีใช้งาน
- Client
  > แบบที่ 1 สร้าง token key แปะไว้ในส่วน Head
    ```
    <?php
      require_once('CSRF.php');
      CSRF::generateToken();  //สร้าง Tokey-key
      CSRF::metaContent();  //เพิ่ม meta csrf_token in head HTML
    ?>
    ```
    Result :
    ```
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>..</title>
        <meta name="csrf_token" content="4f478e462bcb5d507875d4dea663bdababf614292797206a9ccfcd9881abde568d4d04">  
    </head>
    <body></body>
    </html>
    ```
  > แบบที่ 2 สร้าง token key เก็บลง input hidden
    ```
    <?php
      require_once('CSRF.php');
      CSRF::generateToken();  //สร้าง Tokey-key
      CSRF::inputForm();  //เพิ่ม input form
    ?>
    ```
    Result :
    ```
    <form method="POST">
    <input type="hidden" name="csrf_token" value="4f478e462bcb5d507875d4dea663bdababf614292797206a9ccfcd9881abde568d4d04">
    </form>
    ```

- Server
    > ส่ง token key มาที่ Server
    ```
    $.ajax({
      headers: {
          'X-CSRF-TOKEN': document.querySelector(`meta[name="csrf_token"]`).getAttribute('content')
      },
        url: "...",
        method: "GET",
        data: {id:453}
    };
    ```
   > ตรวจสอบ token key
    ```
    <?php
      require_once('CSRF.php');
      if(CSRF::verificationToken()){
        ...
      }
    ?>
    ```

# راهنمای استفاده از اسکریپت با یک کلیک Multi-EasyGost
***
## ممنون:
1. با تشکر از برنامه تونل [gost](https://github.com/ginuerzh/gost) که توسط @ginuerzh توسعه یافته است. استفاده از آن قدرتمند و آسان است. دوستانی که می خواهند بیشتر بدانند می توانند [سند رسمی] را بررسی کنند. https://docs.ginuerzh.xyz/gost/)
2. با تشکر از @风晓晓易易水寒 برای [اسکریپت اصلی] (https://www.fiisi.com/?p=125)
3. به لطف اسکریپت EasyGost که توسط @STSDUST (کتابخانه حذف شده) ارائه شده است، این اسکریپت بر اساس آن اصلاح و بهبود یافته است.
***
## معرفی

> آدرس پروژه و مستندات راهنما:
> https://github.com/KANIKIG/Multi-EasyGost
***
## اسکریپت

* شروع اسکریپت
   `wget --no-check-certificate -O gost.sh https://raw.githubusercontent.com/KANIKIG/Multi-EasyGost/master/gost.sh && chmod +x gost.sh && ./gost.sh`
* برای اجرای مجدد این اسکریپت، کافیست «./gost.sh» را وارد کرده و Enter را فشار دهید

> توجه: از آنجایی که عملکرد gost v2.11.2 پایدار است، این اسکریپت همیشه از این نسخه استفاده می کند و در آینده به روز رسانی رسمی را دنبال نخواهد کرد.

## تابع

### تابع اسکریپت اصلی

- پیاده سازی فایل های پیکربندی systemd و gost برای مدیریت gost
- فعال کردن چندین قانون ارسال به طور همزمان بدون استفاده از ابزارهای دیگر (مانند صفحه نمایش)
- پس از راه اندازی مجدد دستگاه، حمل و نقل خراب نمی شود
- انواع انتقال پشتیبانی شده:
   - ارسال tcp+udp بدون رمزگذاری
   - رمزگذاری رله + tls

### چه چیزی در این اسکریپت جدید است

- اضافه شدن تابع انتخاب نوع انتقال
- انواع حمل و نقل پشتیبانی شده جدید
   - رله + ws
   - رله + wss
- ایجاد پروکسی ss/socks5/http با یک کلیک روی دستگاه کف (گوست داخلی)
- متعادل کننده بار ساده چند قطره که از چندین نوع انتقال پشتیبانی می کند
- اضافه کردن آینه دانلود شتاب داخلی gost
- ایجاد یا حذف ساده وظایف راه اندازی مجدد برنامه ریزی شده
- اسکریپت برای بررسی خودکار به روز رسانی
- آی پی گره خود انتخاب شده CDN را فوروارد کنید
- از گواهی های سفارشی tls پشتیبانی کنید، می توانید هنگام فرود با یک کلیک برای گواهی درخواست دهید و می توانید تأیید گواهی را در حین حمل و نقل فعال کنید

نمایش عملکرد ##

![iShot2020-12-14 PM 05.42.23.png](https://i.loli.net/2020/12/14/q75PO6s2DMIcUKB.png)

![iShot2020-12-14 PM 05.42.39.png](https://i.loli.net/2020/12/14/vzpGlWmPtCrneOY.png)

![2](https://i.loli.net/2020/10/16/fBHgwStVQxc821z.png)

![3](https://i.loli.net/2020/10/16/xgZ6eVAwSzDUFjO.png)

![4](https://i.loli.net/2020/10/16/lt6uAzI5X7yYWhr.png)

![iShot2020-12-14 pm 05.43.46.png](https://i.loli.net/2020/12/14/YjiFTMCKs8lANbI.png)

![iShot2020-12-14 PM 05.43.11.png](https://i.loli.net/2020/12/14/VIcQSsoUaqpzx5T.png)

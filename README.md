# نظام التيسير الذكي 🌿
تطبيق ويب عربي لإدارة طلاب حلقات القرآن الكريم والحضور والمدفوعات، باستخدام HTML/CSS/JavaScript وFirebase Authentication وCloud Firestore.

## التشغيل
1. فعّل Email/Password من Firebase Console > Authentication > Sign-in method.
2. افتح ملف `FIRESTORE_RULES.txt` وانسخ القواعد إلى Firebase Console > Firestore Database > Rules ثم اضغط Publish.
3. افتح `index.html` عبر GitHub Pages وأنشئ حساب إدارة.
4. سجّل الدخول بنفس الحساب على الموبايل والكمبيوتر لمزامنة بيانات هذا الحساب.

## النشر عبر GitHub Pages
من Settings > Pages اختر Deploy from a branch، ثم الفرع `main` والمجلد `/(root)`.
الرابط المتوقع بعد تفعيل Pages: https://marwanelnagar.github.io/smart-system/

## تنبيه أمان
لا تستخدم بيانات طلاب حقيقية قبل نشر قواعد Firestore المحددة. القواعد الحالية تفصل البيانات حسب UID الخاص بالحساب المسجل. هذا إصدار أولي ولا يحتوي على حسابات منفصلة للطلاب أو صلاحيات متعددة للمشرفين.
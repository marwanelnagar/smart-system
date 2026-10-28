const {onCall,HttpsError}=require("firebase-functions/v2/https");
const {defineSecret}=require("firebase-functions/params");
const admin=require("firebase-admin");
const nodemailer=require("nodemailer");
const crypto=require("crypto");
admin.initializeApp();
const db=admin.firestore();
const SMTP_HOST=defineSecret("SMTP_HOST"),SMTP_PORT=defineSecret("SMTP_PORT"),SMTP_USER=defineSecret("SMTP_USER"),SMTP_PASS=defineSecret("SMTP_PASS"),OTP_FROM=defineSecret("OTP_FROM");
const hashCode=(uid,email,code)=>crypto.createHash("sha256").update(uid+"|"+email+"|"+code).digest("hex");
exports.sendEmailOtp=onCall({secrets:[SMTP_HOST,SMTP_PORT,SMTP_USER,SMTP_PASS,OTP_FROM],enforceAppCheck:true},async request=>{
 if(!request.auth) throw new HttpsError("unauthenticated","سجّل الحساب أولًا.");
 const email=String(request.data?.email||"").trim().toLowerCase();
 if(!email||email!==String(request.auth.token.email||"").toLowerCase()) throw new HttpsError("permission-denied","البريد لا يطابق الحساب الحالي.");
 const now=Date.now(),ref=db.collection("emailOtpChallenges").doc(request.auth.uid),snap=await ref.get();
 if(snap.exists && snap.data().lastSentAt && now-snap.data().lastSentAt<60_000) throw new HttpsError("resource-exhausted","انتظر دقيقة قبل طلب رمز جديد.");
 const code=String(crypto.randomInt(0,1000000)).padStart(6,"0");
 await ref.set({email,codeHash:hashCode(request.auth.uid,email,code),expiresAt:now+10*60_000,attempts:0,lastSentAt:now});
 try {
  const transporter=nodemailer.createTransport({host:SMTP_HOST.value(),port:Number(SMTP_PORT.value()),secure:Number(SMTP_PORT.value())===465,auth:{user:SMTP_USER.value(),pass:SMTP_PASS.value()}});
  await transporter.sendMail({from:OTP_FROM.value(),to:email,subject:"رمز التحقق — نظام التيسير الذكي",text:"رمز التحقق الخاص بك هو: "+code+"\nينتهي خلال 10 دقائق. لا تشارك الرمز مع أي شخص.",html:"<div dir='rtl' style='font-family:Arial,sans-serif'><h2>نظام التيسير الذكي</h2><p>رمز التحقق الخاص بك:</p><h1 style='letter-spacing:6px'>"+code+"</h1><p>ينتهي خلال 10 دقائق. لا تشارك الرمز مع أي شخص.</p></div>"});
 } catch(e){await ref.delete();console.error("OTP email send failed",e);throw new HttpsError("internal","تعذر إرسال البريد. راجع إعدادات خدمة البريد في Functions.");}
 return {sent:true};
});
exports.verifyEmailOtp=onCall({enforceAppCheck:true},async request=>{
 if(!request.auth) throw new HttpsError("unauthenticated","سجّل الدخول أولًا.");
 const code=String(request.data?.code||"").trim();
 if(!/^\d{6}$/.test(code)) throw new HttpsError("invalid-argument","أدخل رمزًا مكوّنًا من 6 أرقام.");
 const ref=db.collection("emailOtpChallenges").doc(request.auth.uid);
 const result=await db.runTransaction(async tx=>{
  const snap=await tx.get(ref);if(!snap.exists) throw new HttpsError("failed-precondition","اطلب رمز تحقق جديدًا.");
  const d=snap.data();if(Date.now()>d.expiresAt){tx.delete(ref);throw new HttpsError("deadline-exceeded","انتهت صلاحية الرمز. اطلب رمزًا جديدًا.");}
  if((d.attempts||0)>=5) throw new HttpsError("resource-exhausted","تم تجاوز عدد المحاولات. اطلب رمزًا جديدًا.");
  const expected=Buffer.from(d.codeHash),actual=Buffer.from(hashCode(request.auth.uid,d.email,code));
  if(expected.length!==actual.length||!crypto.timingSafeEqual(expected,actual)){tx.update(ref,{attempts:(d.attempts||0)+1});return false;}
  tx.delete(ref);return true;
 });
 if(!result) throw new HttpsError("permission-denied","الرمز غير صحيح.");
 await admin.auth().updateUser(request.auth.uid,{emailVerified:true});
 return {verified:true};
});
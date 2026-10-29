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

// تحقق البريد قبل إنشاء حساب الإدارة: لا يحتاج المستخدم إلى حساب مسجل مسبقًا.
const emailKey = email => crypto.createHash("sha256").update(String(email).trim().toLowerCase()).digest("hex");
exports.sendRegistrationEmailOtp = onCall({secrets:[SMTP_HOST,SMTP_PORT,SMTP_USER,SMTP_PASS,OTP_FROM],enforceAppCheck:true}, async request => {
 const email=String(request.data?.email||"").trim().toLowerCase();
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new HttpsError("invalid-argument","اكتب بريدًا إلكترونيًا صحيحًا.");
 const key=emailKey(email),ref=db.collection("registrationEmailOtps").doc(key),now=Date.now(),old=await ref.get();
 if(old.exists && now-(old.data().lastSentAt||0)<60_000) throw new HttpsError("resource-exhausted","انتظر دقيقة قبل طلب رمز جديد.");
 const code=String(crypto.randomInt(0,1000000)).padStart(6,"0");
 await ref.set({email,codeHash:crypto.createHash("sha256").update(key+"|"+code).digest("hex"),expiresAt:now+10*60_000,attempts:0,lastSentAt:now});
 try {
  const port=Number(SMTP_PORT.value()),transporter=nodemailer.createTransport({host:SMTP_HOST.value(),port,secure:port===465,auth:{user:SMTP_USER.value(),pass:SMTP_PASS.value()}});
  await transporter.sendMail({from:OTP_FROM.value(),to:email,subject:"رمز إنشاء حساب — نظام التيسير الذكي",text:"رمز التحقق: "+code+"\nصالح لمدة 10 دقائق. لا تشاركه مع أحد.",html:"<div dir='rtl' style='font-family:Arial'><h2>نظام التيسير الذكي</h2><p>رمز التحقق قبل إنشاء الحساب:</p><h1>"+code+"</h1><p>صالح لمدة 10 دقائق. لا تشاركه مع أحد.</p></div>"});
 } catch(e) { await ref.delete(); console.error("registration OTP email failed",e); throw new HttpsError("internal","تعذر إرسال الرمز. راجع إعدادات SMTP في Firebase Functions."); }
 return {sent:true};
});
exports.verifyRegistrationEmailOtp = onCall({enforceAppCheck:true}, async request => {
 const email=String(request.data?.email||"").trim().toLowerCase(),code=String(request.data?.code||"").trim();
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||!/^\d{6}$/.test(code)) throw new HttpsError("invalid-argument","تحقق من البريد والرمز المكوّن من 6 أرقام.");
 const key=emailKey(email),ref=db.collection("registrationEmailOtps").doc(key);
 const ok=await db.runTransaction(async tx=>{
  const snap=await tx.get(ref); if(!snap.exists) throw new HttpsError("failed-precondition","اطلب رمزًا جديدًا.");
  const d=snap.data(); if(Date.now()>d.expiresAt){tx.delete(ref);return false;}
  if((d.attempts||0)>=5) throw new HttpsError("resource-exhausted","تجاوزت عدد المحاولات. اطلب رمزًا جديدًا.");
  const actual=crypto.createHash("sha256").update(key+"|"+code).digest("hex");
  if(actual!==d.codeHash){tx.update(ref,{attempts:(d.attempts||0)+1});return false;}
  tx.delete(ref);tx.set(db.collection("registrationEmailVerified").doc(key),{email,expiresAt:Date.now()+15*60_000});return true;
 });
 if(!ok) throw new HttpsError("permission-denied","الرمز غير صحيح أو انتهت صلاحيته.");
 return {verified:true};
});
exports.completeRegistrationEmailVerification = onCall({enforceAppCheck:true}, async request => {
 if(!request.auth) throw new HttpsError("unauthenticated","أنشئ الحساب بعد تأكيد البريد.");
 const email=String(request.auth.token.email||"").trim().toLowerCase(),key=emailKey(email),ref=db.collection("registrationEmailVerified").doc(key),snap=await ref.get();
 if(!snap.exists||snap.data().expiresAt<Date.now()||snap.data().email!==email) throw new HttpsError("permission-denied","أكد البريد بالرمز قبل إنشاء الحساب.");
 await admin.auth().updateUser(request.auth.uid,{emailVerified:true}); await ref.delete();
 return {verified:true};
});

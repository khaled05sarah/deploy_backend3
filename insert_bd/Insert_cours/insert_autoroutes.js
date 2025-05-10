require('dotenv').config();
const mongoose = require('mongoose');
const Autoroute = require('./models/autoroute');

// 💜 Connexion à MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("✅ Connecté à MongoDB"))
    .catch(err => console.error("❌ Erreur de connexion :", err));
// 💜 Données complètes des autoroutes
const autoroutes = [{
    "explication_generale": ".تشمل الطرقات السيارة على ممرين منفصلين لحركة المرور، حيث يجب على السائقين اتباع قواعد خاصة عند الدخول إليها والخروج منها لضمان سلامة جميع مستعملي الطريق",
    "paragraphes": [{
        "description": "** الدخول إلى الطريق السيار: يجب على السائق الذي يتهيأ للدخول إلى الطريق السيارة - عبر محولات الدخول - أن يزيد في سرعته وذلك عندما يتأكد بواسطة المرآة العاكسة للرؤية من الجهة اليسرى بأن لديه الوقت الكافي للاندماج بين العربات وذلك حسب سرعتها والمسافة التي تفصلها"
    },
    {
        "description": "** عند الخروج من الطريق السيارة يجب الانحياز إلى السبيل الأيمن مع التخفيض تدريجياً في السرعة كلما اقتربت من العلامات العمودية"
    },
    {
        "description": "**يحجر الجولان بالطرقات السيارة على:**\n\n• المترجلين\n• الدراجات والدراجات النارية الصغيرة\n• العربات غير المجرورة آلياً\n• الجرارات والمعدات الفلاحية ومعدات الأشغال العمومية\n• السيارات أو مجموع العربات التي لا تستطيع بلوغ سرعة دنيا بـ 60 كم في الساعة\n• العربات ذات المحرك غير الخاضعة للتسجيل\n• العربات المخصصة للنقل الاستثنائي"
      },
      {
        "description": "**يحجر على السواق القيام بالعمليات التالية على الطرقات السيارة:**\n\n• السير إلى الوراء\n• الرجوع على الأعقاب، لاسيما بعبور الأرض المسطحة الفاصلة بين المعبدين أو استعمال نقاط العبور بها\n• الجولان على جوانب الوقوف الاضطراري"
      },
      
    {
        "description": "** في حالة التوقف الاضطراري للعربة (تعطل العربة بالطريق، حادث، خطر داهم...) يجب على السائق أن يبذل كل ما في وسعه لإخراج العربة من المعبد ومن جانب الوقوف الاضطراري. وإن تعذر عليه ذلك، يعلن عن وجودها بالإشارات القانونية حتى يتمكن بقية السواق من رؤيتها على مسافة كافية"
    },
    {
        "description": "** يجب على السائق في هذه الحالة الإشارة إلى العربة بواسطة مثلث الخطر: يوضع هذا المثلث خلف العربة على مسافة 100 متر بهذه الطريق. يمكن بالإضافة إلى ذلك استعمال وسائل إشارة أخرى، مثل تشغيل أضواء تغيير الاتجاه مع بعضها أو وضع ضوء يدوي رفّاف ذي لون أصفر"
    },
    {
        "description": "** تذكير: لا يمكن استعمال السبيل الثاني إلا عند المجاوزة. عندما تظهر العربة التي وقع تجاوزها في المرآة العاكسة للرؤية الداخلية، تبدأ عملية الرجوع إلى اليمين وتكون بصفة تدريجية. جوانب الوقوف الاضطراري بالطريق السيارة تفصل عن المعبد بخطوط متقطعة يساوي طولها حوالي ثلاث مرات المسافة بينها (المخطط 20 متر والفراغ 6 متر)"
    }
    ],
    "images": [
         "assets/img_181.png",
         "assets/img_182.png",
         "assets/img_183.png"
    ]
}];



Autoroute.insertMany(autoroutes)
    .then(() => {
        console.log("✅ Insertion réussie !");
        mongoose.connection.close();
    })
    .catch(err => {
        console.error("❌ Erreur d'insertion :", err);
        mongoose.connection.close();
    });


async function insertautoroute() {
    try {
        await Autoroute.deleteMany();
        await Autoroute.insertMany(autoroutes);
        console.log("✅ Tous les croisements ont été insérés avec succès !");
        mongoose.connection.close();
    } catch (error) {
        console.error("❌ Erreur lors de l’insertion :", error);
    }
}

insertautoroute();
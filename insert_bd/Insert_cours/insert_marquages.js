require('dotenv').config();
const mongoose = require('mongoose');
const Marquage = require('./models/marquage');

// 💜 Connexion à MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("✅ Connecté à MongoDB"))
    .catch(err => console.error("❌ Erreur de connexion :", err));
// 💜 Données complètes des autoroutes
const marquages = [{
    "explication_generale": "الهدف من هذا الباب هو التعرف على مختلف أنواع  رسوم الطريق :  فهي تنظم حركة المرور و تساعد على الاستعمال السليم للطريق مثل بقية الإشارات الضوئية والعمودية ويفرض وجودها على مستعملي الطريق التزامات معينة تحقيقا للسلامة المرورية",
    "paragraphes": [
        {
            "description":" الخط المتواصل:"
        },
        {
            "description": "يعني منع اجتيازه من طرف كل سائق\n\nلخطوط المحورية أو المحددة للسبل:"
          },
          
          {
            "description": "تحدد هذه الخطوط المسالك و يساوي طولها حوالي ثلث المسافة بينها. لا يمكن اجتيازها إلا عند المجاوزة أو الدوران إلى اليسار أو الرجوع على الأعقاب \n\nخطوط حافة المعبد:"
          },
          
          {
            "description": "يقع تحديد حافتي المعبد بخطوط متقطعة و يساوي طول هذه الخطوط المسافة بينها تقريبا \n\nجوانب الوقوف الاضطراري بالطريق السيار:"
          },
          
          {
            "description": "يقع تحديد جوانب الوقوف الاضطراري بالطريق السيار بخطوط متقطعة و يساوي طول الخطوط ثلاث مرات المسافة بينها تقريبا (المدهون 20 متر والفراغ 6 متر) \n\nخطوط الإعلان عن خط متواصل:"
          },
          
        {
            "description": "تعلن هذه الخطوط عن الاقتراب من الخط المتواصل . وحتى يمكن للسائق القيام بعملية المجاوزة يجب أن يتأكد من إمكانية القيام بها قبل بلوغ الخط المتواصل"
        },
        {
            "description": "إذا كان الطريق مقسما إلى سبيل محدد بخط متقطع يحاذيه خط متواصل، فلا يجوز للسائق أن يأخذ في الاعتبار إلا الخط الموجود بجانبه\n\nأسهم الانزواء:"
          },
          {
            "description": "تسمى أسهم التنبيه وتكون موجهة نحو اليمين، وترسم بين الخطوط المتقطعة للتنبيه عن تحول الخط المتقطع إلى خط متواصل. إذا بدأ السائق في القيام بعملية المجاوزة وهو عند مستوى أسهم الانزواء، فعليه إتمامها قبل الوصول إلى الخط المتواصل\n\nأسهم الاتجاه أو الاختيار:"
          },
          {
            "description": "ترشد مستعملي الطريق إلى المسلك أو السبيل المراد اتباعه، ففي حالة الانعطاف إلى اليمين، يتم اختيار المسلك الذي يحتوي على السهم الموجه نحو اليمين\n\nالخطوط المنكسرة:"
          },
          {
            "description": "هي خطوط متوازية أو منحنية ذات لون أبيض، يمنع الجولان والوقوف والتوقف عليها\n\nممرات المترجلين:"
          },
        {
            "description": " هي خطوط عرضية موازية لمحور المعبد عند الاقتراب من هذه الممرات يجب على السائق التخفيض من السرعة والتوقف عند الاقتضاء لفسح المجال للمترجلين المتوغلين. و يمنع الوقوف و التوقف على هذه الممرات"
        }
    ],
    "images":
    [
        "assets/img_221.png",
        "assets/img_222.png",
        "assets/img_223.png",
        "assets/img_224.png",
        "assets/img_225.png",
        "assets/img_226.png",
        "assets/img_227.png",
        "assets/img_228.png",
        "assets/img_229.png",
        "assets/img_230.png"


    ]
}];



Marquage.insertMany(marquages)
    .then(() => {
        console.log("✅ Insertion réussie !");
        mongoose.connection.close();
    })
    .catch(err => {
        console.error("❌ Erreur d'insertion :", err);
        mongoose.connection.close();
    });


async function insertmarquage() {
    try {
        await Marquage.deleteMany();
        await Marquage.insertMany(marquages);
        console.log("✅ Tout les paragraphes ont été insérés avec succès !");
        mongoose.connection.close();
    } catch (error) {
        console.error("❌ Erreur lors de l’insertion :", error);
    }
}

insertmarquage();
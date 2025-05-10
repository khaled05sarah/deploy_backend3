require('dotenv').config();
const mongoose = require('mongoose');
const Croisement = require('./models/croisement');

// 📌 Connexion à MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("✅ Connecté à MongoDB"))
    .catch(err => console.error("❌ Erreur de connexion :", err));
// 📌 Données complètes des panneaux
const croisements = [{
    "explication_generale": "هذا الباب سوف تتمكن من التعرف على كيفية التصرف عند التعرض لإحدى الحالات التالية:\n\nمقاطعة بطرق بها حواجز أشغال\n\nمقاطعة بمعبر ضيق\n\nمقاطعة صعبة بطريق جبلي\n\nالسؤال المطروح: من يمر أولاً؟ للإجابة عن ذلك يجب التعرف على القواعد الواجب تطبيقها",

    "paragraphes": 
        
            [
                {"description": "**جاء بمجلة الطرقات أن المقاطعة هي موضع العربتين المتحركتين عندما تلتقيان في اتجاه متقابل بسبيلين مختلفين من معبر واحد. تكون المقاطعة على اليمين. على كل سائق أن يترك عند المقاطعة مسافة جانبية كافية وأن ينحاز عند الاقتضاء إلى أقصى اليمين."},

                { "description": "**إن تعذر عليه ذلك بسبب عائق ما، فعليه أن يخفض من سرعته، وعند الاقتضاء أن يتوقف إن كان هناك عائق من جانبه لتمكين مستعملي الطريق القادمين من الاتجاه المعاكس من المرور.\n\nفي هذه الوضعية، تمثل الأشغال الموجودة على الطريق حاجزًا من جهة السيارة الحمراء، لذلك يجب أن تترك أولوية المرور للعربة القادمة من الاتجاه المعاكس. إذًا يجب التخفيض من السرعة، وعند الاقتضاء التوقف." },
                { "description": "**المقاطعة على الطرقات الضيقة: في طريق عادي ضيق، تترك العربة التي يتجاوز حجمها الخارجي أو حمولتها 2 متر عرضًا و7 أمتار طولًا (باعتبارها مقطورة) الأولوية للعربات الخفيفة." },
                { "description": "**استثناء: تتمتع حافلات النقل العمومي داخل مناطق العمران بالأولوية.\n\nبهذا الجزء الضيق من الطريق، يجب أن أخفض من السرعة، وعند الاقتضاء أن أتوقف لفتح مجال المرور لهذه الحافلة." },
                { "description": "**إذا كان الطريق ضيقًا بالأنفاق والجسور، سوف تعترضني علامة فتح المجال والأولوية. فإذا كان إطار العلامة أحمر، أفسح مجال المرور، أما إذا كان الإطار أزرق، أتمتع بالأولوية.\n\nعند وجود هذه العلامة: يجب على العربات القادمة من الاتجاه المعاكس فسح مجال المرور." },
                { "description": "**عند وجود هذه العلامة: أفسح المجال للعربات القادمة من الاتجاه المعاكس." },
                { "description": "**المقاطعة بالطرقات الجبلية المنحدرة: في طريق جبلي ضيق، تترك العربة النازلة الأولوية للعربة الصاعدة. بهذه الطريق الضيقة والمنحدرة، يجب أن أترك الأولوية للسيارة الحمراء الصاعدة." },
                { "description": "**استثناء: تترك السيارة الصاعدة الأولوية للعربة التي يتجاوز حجمها الخارجي أو حمولتها 2 متر عرضًا و7 أمتار طولًا (باعتبارها مقطورة)." }
            ],
            
        
    "images": [
        "assets/img_173.png",
        "assets/img_174.png",
        "assets/img_175.png",
        "assets/img_176.png",
       "assets/img_179.png" ,
        "assets/img_180.png",
        "assets/img_177.png",
        "assets/img_178.png",
        
    ]
}];

Croisement.insertMany(croisements)
    .then(() => {
        console.log("✅ Insertion réussie !");
        mongoose.connection.close();
    })
    .catch(err => {
        console.error("❌ Erreur d'insertion :", err);
        mongoose.connection.close();
    });



async function insertcroisement() {
    try {
        await Croisement.deleteMany();
        await Croisement.insertMany(croisements);
        console.log("✅ Tous les croisements ont été insérés avec succès !");
        mongoose.connection.close();
    } catch (error) {
        console.error("❌ Erreur lors de l’insertion :", error);
    }
}
insertcroisement();
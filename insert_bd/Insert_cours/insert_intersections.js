require('dotenv').config();
const mongoose = require('mongoose');
const Intersection = require('./models/intersection');

// 💜 Connexion à MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("✅ Connecté à MongoDB"))
    .catch(err => console.error("❌ Erreur de connexion :", err));
// 💜 Données complètes des autoroutes
const intersections = [{
    "explication_generale": ".الهدف من هذا الباب هو معرفة الاحتياطات الواجب اتخاذها قبل الانعطاف إلى اليمين أو الى اليسار لسلك طريق أخرى أو للدخول إلى ملك مجاور",
    "paragraphes": [{
            "description": " وقبل مغادرة الطريق يجب أن يحترم قواعد الأولوية _ \n أن يتفقد المرايا العاكسة للرؤية  _\n أن يتأكد من إمكانية القيام بالمناورة_ \n أن ينبه مسبقا بنيته للدوران وذلك بتشغيل إشارات تشغيل الاتجاه _ \nأن يتجنب الضغط على الفرامل بقوة حتى لا يفاجئ العربات التي تسير وراءه _\n:وقبل التخفيض من السرعة يجب•\n.حتى يمكن الدوران يجب السير  بسرعة معتدلة •\n.أن يتأكد من عدم وجود علامة تمنعه من التوغل في المفترق_\nأن يتأكد من أن المعبد الذي يريد التوغل فيه مفتوح للجولان_\n :عند تغيير الاتجاه بالمفترقات, يجب على كل سائق أخذ الاحتياطات التالية \nالإحتياطات الواجب إتخاذها  قبل الدوران"
        },
        {
            "description": "للدوران إلى اليمين على السائق أن ينحاز بقدر الإمكان إلى الحافة اليمنى للمعبد, وأن يقوم بهذه العملية قدر الإمكان في فضاء ضيق "
        },
        {
            "description": ":للدوران لليسار يجب الانحياز n\   بقدر الإمكان إلى محور المعبد إذا كان الجولان في الاتجاهين_ n\  أو إلى الحافة اليسرى من المعبد إذا كان الجولان في اتجاه واحد_"
        },
        {
            "description": "إذا كان المعبد يحتوي على أكثر من سبيل، يتابع السائق سيره ويسلك السبيل الذي يحتوي على السهم الموجه نحو اليسار.\n\n• عند تغيير الاتجاه يجب على السائق فسح مجال المرور:\n\n- للعربات القادمة من الاتجاه المعاكس على المعبد الذي يتأهب لمبارحته.\n- للدراجات والدراجات النارية المتجولة على المعبد الذي يتأهب لسلوكه.\n- للمترجلين الذين يجتازون ذلك المعبد.\n\n• وعند إتمام عملية المناورة يجب على السائق توقيف إشارات تغيير الاتجاه."
        }

    ]

}];



Intersection.insertMany(intersections)
    .then(() => {
        console.log("✅ Insertion réussie !");
        mongoose.connection.close();
    })
    .catch(err => {
        console.error("❌ Erreur d'insertion :", err);
        mongoose.connection.close();
    });


async function insertintersection() {
    try {
        await Intersection.deleteMany();
        await Intersection.insertMany(intersections);
        console.log("✅ Tout les paragraphes ont été insérés avec succès !");
        mongoose.connection.close();
    } catch (error) {
        console.error("❌ Erreur lors de l’insertion :", error);
    }
}

insertintersection();
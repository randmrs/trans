#include "defines.p4"
#include "headers.p4"

control process_encrypt(
    inout headers hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata) {

    action permutation_plaintext_1 () {
        hdr.dp_1.bit_0 = (hdr.plaintext_1.value >> hdr.p.pos0)[0:0];
        hdr.dp_1.bit_1 = (hdr.plaintext_1.value >> hdr.p.pos1)[0:0];
        hdr.dp_1.bit_2 = (hdr.plaintext_1.value >> hdr.p.pos2)[0:0];
        hdr.dp_1.bit_3 = (hdr.plaintext_1.value >> hdr.p.pos3)[0:0];
        hdr.dp_1.bit_4 = (hdr.plaintext_1.value >> hdr.p.pos4)[0:0];
        hdr.dp_1.bit_5 = (hdr.plaintext_1.value >> hdr.p.pos5)[0:0];
        hdr.dp_1.bit_6 = (hdr.plaintext_1.value >> hdr.p.pos6)[0:0];
        hdr.dp_1.bit_7 = (hdr.plaintext_1.value >> hdr.p.pos7)[0:0];
        hdr.dp_1.bit_8 = (hdr.plaintext_1.value >> hdr.p.pos8)[0:0];
        hdr.dp_1.bit_9 = (hdr.plaintext_1.value >> hdr.p.pos9)[0:0];
        hdr.dp_1.bit_10 = (hdr.plaintext_1.value >> hdr.p.pos10)[0:0];
        hdr.dp_1.bit_11 = (hdr.plaintext_1.value >> hdr.p.pos11)[0:0];
        hdr.dp_1.bit_12 = (hdr.plaintext_1.value >> hdr.p.pos12)[0:0];
        hdr.dp_1.bit_13 = (hdr.plaintext_1.value >> hdr.p.pos13)[0:0];
        hdr.dp_1.bit_14 = (hdr.plaintext_1.value >> hdr.p.pos14)[0:0];
        hdr.dp_1.bit_15 = (hdr.plaintext_1.value >> hdr.p.pos15)[0:0];
        hdr.dp_1.bit_16 = (hdr.plaintext_1.value >> hdr.p.pos16)[0:0];
        hdr.dp_1.bit_17 = (hdr.plaintext_1.value >> hdr.p.pos17)[0:0];
        hdr.dp_1.bit_18 = (hdr.plaintext_1.value >> hdr.p.pos18)[0:0];
        hdr.dp_1.bit_19 = (hdr.plaintext_1.value >> hdr.p.pos19)[0:0];
        hdr.dp_1.bit_20 = (hdr.plaintext_1.value >> hdr.p.pos20)[0:0];
        hdr.dp_1.bit_21 = (hdr.plaintext_1.value >> hdr.p.pos21)[0:0];
        hdr.dp_1.bit_22 = (hdr.plaintext_1.value >> hdr.p.pos22)[0:0];
        hdr.dp_1.bit_23 = (hdr.plaintext_1.value >> hdr.p.pos23)[0:0];
        hdr.dp_1.bit_24 = (hdr.plaintext_1.value >> hdr.p.pos24)[0:0];
        hdr.dp_1.bit_25 = (hdr.plaintext_1.value >> hdr.p.pos25)[0:0];
        hdr.dp_1.bit_26 = (hdr.plaintext_1.value >> hdr.p.pos26)[0:0];
        hdr.dp_1.bit_27 = (hdr.plaintext_1.value >> hdr.p.pos27)[0:0];
        hdr.dp_1.bit_28 = (hdr.plaintext_1.value >> hdr.p.pos28)[0:0];
        hdr.dp_1.bit_29 = (hdr.plaintext_1.value >> hdr.p.pos29)[0:0];
        hdr.dp_1.bit_30 = (hdr.plaintext_1.value >> hdr.p.pos30)[0:0];
        hdr.dp_1.bit_31 = (hdr.plaintext_1.value >> hdr.p.pos31)[0:0];
        hdr.dp_1.bit_32 = (hdr.plaintext_1.value >> hdr.p.pos32)[0:0];
        hdr.dp_1.bit_33 = (hdr.plaintext_1.value >> hdr.p.pos33)[0:0];
        hdr.dp_1.bit_34 = (hdr.plaintext_1.value >> hdr.p.pos34)[0:0];
        hdr.dp_1.bit_35 = (hdr.plaintext_1.value >> hdr.p.pos35)[0:0];
        hdr.dp_1.bit_36 = (hdr.plaintext_1.value >> hdr.p.pos36)[0:0];
        hdr.dp_1.bit_37 = (hdr.plaintext_1.value >> hdr.p.pos37)[0:0];
        hdr.dp_1.bit_38 = (hdr.plaintext_1.value >> hdr.p.pos38)[0:0];
        hdr.dp_1.bit_39 = (hdr.plaintext_1.value >> hdr.p.pos39)[0:0];
        hdr.dp_1.bit_40 = (hdr.plaintext_1.value >> hdr.p.pos40)[0:0];
        hdr.dp_1.bit_41 = (hdr.plaintext_1.value >> hdr.p.pos41)[0:0];
        hdr.dp_1.bit_42 = (hdr.plaintext_1.value >> hdr.p.pos42)[0:0];
        hdr.dp_1.bit_43 = (hdr.plaintext_1.value >> hdr.p.pos43)[0:0];
        hdr.dp_1.bit_44 = (hdr.plaintext_1.value >> hdr.p.pos44)[0:0];
        hdr.dp_1.bit_45 = (hdr.plaintext_1.value >> hdr.p.pos45)[0:0];
        hdr.dp_1.bit_46 = (hdr.plaintext_1.value >> hdr.p.pos46)[0:0];
        hdr.dp_1.bit_47 = (hdr.plaintext_1.value >> hdr.p.pos47)[0:0];
        hdr.dp_1.bit_48 = (hdr.plaintext_1.value >> hdr.p.pos48)[0:0];
        hdr.dp_1.bit_49 = (hdr.plaintext_1.value >> hdr.p.pos49)[0:0];
        hdr.dp_1.bit_50 = (hdr.plaintext_1.value >> hdr.p.pos50)[0:0];
        hdr.dp_1.bit_51 = (hdr.plaintext_1.value >> hdr.p.pos51)[0:0];
        hdr.dp_1.bit_52 = (hdr.plaintext_1.value >> hdr.p.pos52)[0:0];
        hdr.dp_1.bit_53 = (hdr.plaintext_1.value >> hdr.p.pos53)[0:0];
        hdr.dp_1.bit_54 = (hdr.plaintext_1.value >> hdr.p.pos54)[0:0];
        hdr.dp_1.bit_55 = (hdr.plaintext_1.value >> hdr.p.pos55)[0:0];
        hdr.dp_1.bit_56 = (hdr.plaintext_1.value >> hdr.p.pos56)[0:0];
        hdr.dp_1.bit_57 = (hdr.plaintext_1.value >> hdr.p.pos57)[0:0];
        hdr.dp_1.bit_58 = (hdr.plaintext_1.value >> hdr.p.pos58)[0:0];
        hdr.dp_1.bit_59 = (hdr.plaintext_1.value >> hdr.p.pos59)[0:0];
        hdr.dp_1.bit_60 = (hdr.plaintext_1.value >> hdr.p.pos60)[0:0];
        hdr.dp_1.bit_61 = (hdr.plaintext_1.value >> hdr.p.pos61)[0:0];
        hdr.dp_1.bit_62 = (hdr.plaintext_1.value >> hdr.p.pos62)[0:0];
        hdr.dp_1.bit_63 = (hdr.plaintext_1.value >> hdr.p.pos63)[0:0];
        hdr.dp_1.bit_64 = (hdr.plaintext_1.value >> hdr.p.pos64)[0:0];
        hdr.dp_1.bit_65 = (hdr.plaintext_1.value >> hdr.p.pos65)[0:0];
        hdr.dp_1.bit_66 = (hdr.plaintext_1.value >> hdr.p.pos66)[0:0];
        hdr.dp_1.bit_67 = (hdr.plaintext_1.value >> hdr.p.pos67)[0:0];
        hdr.dp_1.bit_68 = (hdr.plaintext_1.value >> hdr.p.pos68)[0:0];
        hdr.dp_1.bit_69 = (hdr.plaintext_1.value >> hdr.p.pos69)[0:0];
        hdr.dp_1.bit_70 = (hdr.plaintext_1.value >> hdr.p.pos70)[0:0];
        hdr.dp_1.bit_71 = (hdr.plaintext_1.value >> hdr.p.pos71)[0:0];
        hdr.dp_1.bit_72 = (hdr.plaintext_1.value >> hdr.p.pos72)[0:0];
        hdr.dp_1.bit_73 = (hdr.plaintext_1.value >> hdr.p.pos73)[0:0];
        hdr.dp_1.bit_74 = (hdr.plaintext_1.value >> hdr.p.pos74)[0:0];
        hdr.dp_1.bit_75 = (hdr.plaintext_1.value >> hdr.p.pos75)[0:0];
        hdr.dp_1.bit_76 = (hdr.plaintext_1.value >> hdr.p.pos76)[0:0];
        hdr.dp_1.bit_77 = (hdr.plaintext_1.value >> hdr.p.pos77)[0:0];
        hdr.dp_1.bit_78 = (hdr.plaintext_1.value >> hdr.p.pos78)[0:0];
        hdr.dp_1.bit_79 = (hdr.plaintext_1.value >> hdr.p.pos79)[0:0];
        hdr.dp_1.bit_80 = (hdr.plaintext_1.value >> hdr.p.pos80)[0:0];
        hdr.dp_1.bit_81 = (hdr.plaintext_1.value >> hdr.p.pos81)[0:0];
        hdr.dp_1.bit_82 = (hdr.plaintext_1.value >> hdr.p.pos82)[0:0];
        hdr.dp_1.bit_83 = (hdr.plaintext_1.value >> hdr.p.pos83)[0:0];
        hdr.dp_1.bit_84 = (hdr.plaintext_1.value >> hdr.p.pos84)[0:0];
        hdr.dp_1.bit_85 = (hdr.plaintext_1.value >> hdr.p.pos85)[0:0];
        hdr.dp_1.bit_86 = (hdr.plaintext_1.value >> hdr.p.pos86)[0:0];
        hdr.dp_1.bit_87 = (hdr.plaintext_1.value >> hdr.p.pos87)[0:0];
        hdr.dp_1.bit_88 = (hdr.plaintext_1.value >> hdr.p.pos88)[0:0];
        hdr.dp_1.bit_89 = (hdr.plaintext_1.value >> hdr.p.pos89)[0:0];
        hdr.dp_1.bit_90 = (hdr.plaintext_1.value >> hdr.p.pos90)[0:0];
        hdr.dp_1.bit_91 = (hdr.plaintext_1.value >> hdr.p.pos91)[0:0];
        hdr.dp_1.bit_92 = (hdr.plaintext_1.value >> hdr.p.pos92)[0:0];
        hdr.dp_1.bit_93 = (hdr.plaintext_1.value >> hdr.p.pos93)[0:0];
        hdr.dp_1.bit_94 = (hdr.plaintext_1.value >> hdr.p.pos94)[0:0];
        hdr.dp_1.bit_95 = (hdr.plaintext_1.value >> hdr.p.pos95)[0:0];
        hdr.dp_1.bit_96 = (hdr.plaintext_1.value >> hdr.p.pos96)[0:0];
        hdr.dp_1.bit_97 = (hdr.plaintext_1.value >> hdr.p.pos97)[0:0];
        hdr.dp_1.bit_98 = (hdr.plaintext_1.value >> hdr.p.pos98)[0:0];
        hdr.dp_1.bit_99 = (hdr.plaintext_1.value >> hdr.p.pos99)[0:0];
        hdr.dp_1.bit_100 = (hdr.plaintext_1.value >> hdr.p.pos100)[0:0];
        hdr.dp_1.bit_101 = (hdr.plaintext_1.value >> hdr.p.pos101)[0:0];
        hdr.dp_1.bit_102 = (hdr.plaintext_1.value >> hdr.p.pos102)[0:0];
        hdr.dp_1.bit_103 = (hdr.plaintext_1.value >> hdr.p.pos103)[0:0];
        hdr.dp_1.bit_104 = (hdr.plaintext_1.value >> hdr.p.pos104)[0:0];
        hdr.dp_1.bit_105 = (hdr.plaintext_1.value >> hdr.p.pos105)[0:0];
        hdr.dp_1.bit_106 = (hdr.plaintext_1.value >> hdr.p.pos106)[0:0];
        hdr.dp_1.bit_107 = (hdr.plaintext_1.value >> hdr.p.pos107)[0:0];
        hdr.dp_1.bit_108 = (hdr.plaintext_1.value >> hdr.p.pos108)[0:0];
        hdr.dp_1.bit_109 = (hdr.plaintext_1.value >> hdr.p.pos109)[0:0];
        hdr.dp_1.bit_110 = (hdr.plaintext_1.value >> hdr.p.pos110)[0:0];
        hdr.dp_1.bit_111 = (hdr.plaintext_1.value >> hdr.p.pos111)[0:0];
        hdr.dp_1.bit_112 = (hdr.plaintext_1.value >> hdr.p.pos112)[0:0];
        hdr.dp_1.bit_113 = (hdr.plaintext_1.value >> hdr.p.pos113)[0:0];
        hdr.dp_1.bit_114 = (hdr.plaintext_1.value >> hdr.p.pos114)[0:0];
        hdr.dp_1.bit_115 = (hdr.plaintext_1.value >> hdr.p.pos115)[0:0];
        hdr.dp_1.bit_116 = (hdr.plaintext_1.value >> hdr.p.pos116)[0:0];
        hdr.dp_1.bit_117 = (hdr.plaintext_1.value >> hdr.p.pos117)[0:0];
        hdr.dp_1.bit_118 = (hdr.plaintext_1.value >> hdr.p.pos118)[0:0];
        hdr.dp_1.bit_119 = (hdr.plaintext_1.value >> hdr.p.pos119)[0:0];
        hdr.dp_1.bit_120 = (hdr.plaintext_1.value >> hdr.p.pos120)[0:0];
        hdr.dp_1.bit_121 = (hdr.plaintext_1.value >> hdr.p.pos121)[0:0];
        hdr.dp_1.bit_122 = (hdr.plaintext_1.value >> hdr.p.pos122)[0:0];
        hdr.dp_1.bit_123 = (hdr.plaintext_1.value >> hdr.p.pos123)[0:0];
        hdr.dp_1.bit_124 = (hdr.plaintext_1.value >> hdr.p.pos124)[0:0];
        hdr.dp_1.bit_125 = (hdr.plaintext_1.value >> hdr.p.pos125)[0:0];
        hdr.dp_1.bit_126 = (hdr.plaintext_1.value >> hdr.p.pos126)[0:0];
        hdr.dp_1.bit_127 = (hdr.plaintext_1.value >> hdr.p.pos127)[0:0];
    }

    action permutation_plaintext_2 () {
        hdr.dp_2.bit_0 = (hdr.plaintext_2.value >> hdr.p.pos0)[0:0];
        hdr.dp_2.bit_1 = (hdr.plaintext_2.value >> hdr.p.pos1)[0:0];
        hdr.dp_2.bit_2 = (hdr.plaintext_2.value >> hdr.p.pos2)[0:0];
        hdr.dp_2.bit_3 = (hdr.plaintext_2.value >> hdr.p.pos3)[0:0];
        hdr.dp_2.bit_4 = (hdr.plaintext_2.value >> hdr.p.pos4)[0:0];
        hdr.dp_2.bit_5 = (hdr.plaintext_2.value >> hdr.p.pos5)[0:0];
        hdr.dp_2.bit_6 = (hdr.plaintext_2.value >> hdr.p.pos6)[0:0];
        hdr.dp_2.bit_7 = (hdr.plaintext_2.value >> hdr.p.pos7)[0:0];
        hdr.dp_2.bit_8 = (hdr.plaintext_2.value >> hdr.p.pos8)[0:0];
        hdr.dp_2.bit_9 = (hdr.plaintext_2.value >> hdr.p.pos9)[0:0];
        hdr.dp_2.bit_10 = (hdr.plaintext_2.value >> hdr.p.pos10)[0:0];
        hdr.dp_2.bit_11 = (hdr.plaintext_2.value >> hdr.p.pos11)[0:0];
        hdr.dp_2.bit_12 = (hdr.plaintext_2.value >> hdr.p.pos12)[0:0];
        hdr.dp_2.bit_13 = (hdr.plaintext_2.value >> hdr.p.pos13)[0:0];
        hdr.dp_2.bit_14 = (hdr.plaintext_2.value >> hdr.p.pos14)[0:0];
        hdr.dp_2.bit_15 = (hdr.plaintext_2.value >> hdr.p.pos15)[0:0];
        hdr.dp_2.bit_16 = (hdr.plaintext_2.value >> hdr.p.pos16)[0:0];
        hdr.dp_2.bit_17 = (hdr.plaintext_2.value >> hdr.p.pos17)[0:0];
        hdr.dp_2.bit_18 = (hdr.plaintext_2.value >> hdr.p.pos18)[0:0];
        hdr.dp_2.bit_19 = (hdr.plaintext_2.value >> hdr.p.pos19)[0:0];
        hdr.dp_2.bit_20 = (hdr.plaintext_2.value >> hdr.p.pos20)[0:0];
        hdr.dp_2.bit_21 = (hdr.plaintext_2.value >> hdr.p.pos21)[0:0];
        hdr.dp_2.bit_22 = (hdr.plaintext_2.value >> hdr.p.pos22)[0:0];
        hdr.dp_2.bit_23 = (hdr.plaintext_2.value >> hdr.p.pos23)[0:0];
        hdr.dp_2.bit_24 = (hdr.plaintext_2.value >> hdr.p.pos24)[0:0];
        hdr.dp_2.bit_25 = (hdr.plaintext_2.value >> hdr.p.pos25)[0:0];
        hdr.dp_2.bit_26 = (hdr.plaintext_2.value >> hdr.p.pos26)[0:0];
        hdr.dp_2.bit_27 = (hdr.plaintext_2.value >> hdr.p.pos27)[0:0];
        hdr.dp_2.bit_28 = (hdr.plaintext_2.value >> hdr.p.pos28)[0:0];
        hdr.dp_2.bit_29 = (hdr.plaintext_2.value >> hdr.p.pos29)[0:0];
        hdr.dp_2.bit_30 = (hdr.plaintext_2.value >> hdr.p.pos30)[0:0];
        hdr.dp_2.bit_31 = (hdr.plaintext_2.value >> hdr.p.pos31)[0:0];
        hdr.dp_2.bit_32 = (hdr.plaintext_2.value >> hdr.p.pos32)[0:0];
        hdr.dp_2.bit_33 = (hdr.plaintext_2.value >> hdr.p.pos33)[0:0];
        hdr.dp_2.bit_34 = (hdr.plaintext_2.value >> hdr.p.pos34)[0:0];
        hdr.dp_2.bit_35 = (hdr.plaintext_2.value >> hdr.p.pos35)[0:0];
        hdr.dp_2.bit_36 = (hdr.plaintext_2.value >> hdr.p.pos36)[0:0];
        hdr.dp_2.bit_37 = (hdr.plaintext_2.value >> hdr.p.pos37)[0:0];
        hdr.dp_2.bit_38 = (hdr.plaintext_2.value >> hdr.p.pos38)[0:0];
        hdr.dp_2.bit_39 = (hdr.plaintext_2.value >> hdr.p.pos39)[0:0];
        hdr.dp_2.bit_40 = (hdr.plaintext_2.value >> hdr.p.pos40)[0:0];
        hdr.dp_2.bit_41 = (hdr.plaintext_2.value >> hdr.p.pos41)[0:0];
        hdr.dp_2.bit_42 = (hdr.plaintext_2.value >> hdr.p.pos42)[0:0];
        hdr.dp_2.bit_43 = (hdr.plaintext_2.value >> hdr.p.pos43)[0:0];
        hdr.dp_2.bit_44 = (hdr.plaintext_2.value >> hdr.p.pos44)[0:0];
        hdr.dp_2.bit_45 = (hdr.plaintext_2.value >> hdr.p.pos45)[0:0];
        hdr.dp_2.bit_46 = (hdr.plaintext_2.value >> hdr.p.pos46)[0:0];
        hdr.dp_2.bit_47 = (hdr.plaintext_2.value >> hdr.p.pos47)[0:0];
        hdr.dp_2.bit_48 = (hdr.plaintext_2.value >> hdr.p.pos48)[0:0];
        hdr.dp_2.bit_49 = (hdr.plaintext_2.value >> hdr.p.pos49)[0:0];
        hdr.dp_2.bit_50 = (hdr.plaintext_2.value >> hdr.p.pos50)[0:0];
        hdr.dp_2.bit_51 = (hdr.plaintext_2.value >> hdr.p.pos51)[0:0];
        hdr.dp_2.bit_52 = (hdr.plaintext_2.value >> hdr.p.pos52)[0:0];
        hdr.dp_2.bit_53 = (hdr.plaintext_2.value >> hdr.p.pos53)[0:0];
        hdr.dp_2.bit_54 = (hdr.plaintext_2.value >> hdr.p.pos54)[0:0];
        hdr.dp_2.bit_55 = (hdr.plaintext_2.value >> hdr.p.pos55)[0:0];
        hdr.dp_2.bit_56 = (hdr.plaintext_2.value >> hdr.p.pos56)[0:0];
        hdr.dp_2.bit_57 = (hdr.plaintext_2.value >> hdr.p.pos57)[0:0];
        hdr.dp_2.bit_58 = (hdr.plaintext_2.value >> hdr.p.pos58)[0:0];
        hdr.dp_2.bit_59 = (hdr.plaintext_2.value >> hdr.p.pos59)[0:0];
        hdr.dp_2.bit_60 = (hdr.plaintext_2.value >> hdr.p.pos60)[0:0];
        hdr.dp_2.bit_61 = (hdr.plaintext_2.value >> hdr.p.pos61)[0:0];
        hdr.dp_2.bit_62 = (hdr.plaintext_2.value >> hdr.p.pos62)[0:0];
        hdr.dp_2.bit_63 = (hdr.plaintext_2.value >> hdr.p.pos63)[0:0];
        hdr.dp_2.bit_64 = (hdr.plaintext_2.value >> hdr.p.pos64)[0:0];
        hdr.dp_2.bit_65 = (hdr.plaintext_2.value >> hdr.p.pos65)[0:0];
        hdr.dp_2.bit_66 = (hdr.plaintext_2.value >> hdr.p.pos66)[0:0];
        hdr.dp_2.bit_67 = (hdr.plaintext_2.value >> hdr.p.pos67)[0:0];
        hdr.dp_2.bit_68 = (hdr.plaintext_2.value >> hdr.p.pos68)[0:0];
        hdr.dp_2.bit_69 = (hdr.plaintext_2.value >> hdr.p.pos69)[0:0];
        hdr.dp_2.bit_70 = (hdr.plaintext_2.value >> hdr.p.pos70)[0:0];
        hdr.dp_2.bit_71 = (hdr.plaintext_2.value >> hdr.p.pos71)[0:0];
        hdr.dp_2.bit_72 = (hdr.plaintext_2.value >> hdr.p.pos72)[0:0];
        hdr.dp_2.bit_73 = (hdr.plaintext_2.value >> hdr.p.pos73)[0:0];
        hdr.dp_2.bit_74 = (hdr.plaintext_2.value >> hdr.p.pos74)[0:0];
        hdr.dp_2.bit_75 = (hdr.plaintext_2.value >> hdr.p.pos75)[0:0];
        hdr.dp_2.bit_76 = (hdr.plaintext_2.value >> hdr.p.pos76)[0:0];
        hdr.dp_2.bit_77 = (hdr.plaintext_2.value >> hdr.p.pos77)[0:0];
        hdr.dp_2.bit_78 = (hdr.plaintext_2.value >> hdr.p.pos78)[0:0];
        hdr.dp_2.bit_79 = (hdr.plaintext_2.value >> hdr.p.pos79)[0:0];
        hdr.dp_2.bit_80 = (hdr.plaintext_2.value >> hdr.p.pos80)[0:0];
        hdr.dp_2.bit_81 = (hdr.plaintext_2.value >> hdr.p.pos81)[0:0];
        hdr.dp_2.bit_82 = (hdr.plaintext_2.value >> hdr.p.pos82)[0:0];
        hdr.dp_2.bit_83 = (hdr.plaintext_2.value >> hdr.p.pos83)[0:0];
        hdr.dp_2.bit_84 = (hdr.plaintext_2.value >> hdr.p.pos84)[0:0];
        hdr.dp_2.bit_85 = (hdr.plaintext_2.value >> hdr.p.pos85)[0:0];
        hdr.dp_2.bit_86 = (hdr.plaintext_2.value >> hdr.p.pos86)[0:0];
        hdr.dp_2.bit_87 = (hdr.plaintext_2.value >> hdr.p.pos87)[0:0];
        hdr.dp_2.bit_88 = (hdr.plaintext_2.value >> hdr.p.pos88)[0:0];
        hdr.dp_2.bit_89 = (hdr.plaintext_2.value >> hdr.p.pos89)[0:0];
        hdr.dp_2.bit_90 = (hdr.plaintext_2.value >> hdr.p.pos90)[0:0];
        hdr.dp_2.bit_91 = (hdr.plaintext_2.value >> hdr.p.pos91)[0:0];
        hdr.dp_2.bit_92 = (hdr.plaintext_2.value >> hdr.p.pos92)[0:0];
        hdr.dp_2.bit_93 = (hdr.plaintext_2.value >> hdr.p.pos93)[0:0];
        hdr.dp_2.bit_94 = (hdr.plaintext_2.value >> hdr.p.pos94)[0:0];
        hdr.dp_2.bit_95 = (hdr.plaintext_2.value >> hdr.p.pos95)[0:0];
        hdr.dp_2.bit_96 = (hdr.plaintext_2.value >> hdr.p.pos96)[0:0];
        hdr.dp_2.bit_97 = (hdr.plaintext_2.value >> hdr.p.pos97)[0:0];
        hdr.dp_2.bit_98 = (hdr.plaintext_2.value >> hdr.p.pos98)[0:0];
        hdr.dp_2.bit_99 = (hdr.plaintext_2.value >> hdr.p.pos99)[0:0];
        hdr.dp_2.bit_100 = (hdr.plaintext_2.value >> hdr.p.pos100)[0:0];
        hdr.dp_2.bit_101 = (hdr.plaintext_2.value >> hdr.p.pos101)[0:0];
        hdr.dp_2.bit_102 = (hdr.plaintext_2.value >> hdr.p.pos102)[0:0];
        hdr.dp_2.bit_103 = (hdr.plaintext_2.value >> hdr.p.pos103)[0:0];
        hdr.dp_2.bit_104 = (hdr.plaintext_2.value >> hdr.p.pos104)[0:0];
        hdr.dp_2.bit_105 = (hdr.plaintext_2.value >> hdr.p.pos105)[0:0];
        hdr.dp_2.bit_106 = (hdr.plaintext_2.value >> hdr.p.pos106)[0:0];
        hdr.dp_2.bit_107 = (hdr.plaintext_2.value >> hdr.p.pos107)[0:0];
        hdr.dp_2.bit_108 = (hdr.plaintext_2.value >> hdr.p.pos108)[0:0];
        hdr.dp_2.bit_109 = (hdr.plaintext_2.value >> hdr.p.pos109)[0:0];
        hdr.dp_2.bit_110 = (hdr.plaintext_2.value >> hdr.p.pos110)[0:0];
        hdr.dp_2.bit_111 = (hdr.plaintext_2.value >> hdr.p.pos111)[0:0];
        hdr.dp_2.bit_112 = (hdr.plaintext_2.value >> hdr.p.pos112)[0:0];
        hdr.dp_2.bit_113 = (hdr.plaintext_2.value >> hdr.p.pos113)[0:0];
        hdr.dp_2.bit_114 = (hdr.plaintext_2.value >> hdr.p.pos114)[0:0];
        hdr.dp_2.bit_115 = (hdr.plaintext_2.value >> hdr.p.pos115)[0:0];
        hdr.dp_2.bit_116 = (hdr.plaintext_2.value >> hdr.p.pos116)[0:0];
        hdr.dp_2.bit_117 = (hdr.plaintext_2.value >> hdr.p.pos117)[0:0];
        hdr.dp_2.bit_118 = (hdr.plaintext_2.value >> hdr.p.pos118)[0:0];
        hdr.dp_2.bit_119 = (hdr.plaintext_2.value >> hdr.p.pos119)[0:0];
        hdr.dp_2.bit_120 = (hdr.plaintext_2.value >> hdr.p.pos120)[0:0];
        hdr.dp_2.bit_121 = (hdr.plaintext_2.value >> hdr.p.pos121)[0:0];
        hdr.dp_2.bit_122 = (hdr.plaintext_2.value >> hdr.p.pos122)[0:0];
        hdr.dp_2.bit_123 = (hdr.plaintext_2.value >> hdr.p.pos123)[0:0];
        hdr.dp_2.bit_124 = (hdr.plaintext_2.value >> hdr.p.pos124)[0:0];
        hdr.dp_2.bit_125 = (hdr.plaintext_2.value >> hdr.p.pos125)[0:0];
        hdr.dp_2.bit_126 = (hdr.plaintext_2.value >> hdr.p.pos126)[0:0];
        hdr.dp_2.bit_127 = (hdr.plaintext_2.value >> hdr.p.pos127)[0:0];
    }

    action permutation_plaintext_3 () {
        hdr.dp_3.bit_0 = (hdr.plaintext_3.value >> hdr.p.pos0)[0:0];
        hdr.dp_3.bit_1 = (hdr.plaintext_3.value >> hdr.p.pos1)[0:0];
        hdr.dp_3.bit_2 = (hdr.plaintext_3.value >> hdr.p.pos2)[0:0];
        hdr.dp_3.bit_3 = (hdr.plaintext_3.value >> hdr.p.pos3)[0:0];
        hdr.dp_3.bit_4 = (hdr.plaintext_3.value >> hdr.p.pos4)[0:0];
        hdr.dp_3.bit_5 = (hdr.plaintext_3.value >> hdr.p.pos5)[0:0];
        hdr.dp_3.bit_6 = (hdr.plaintext_3.value >> hdr.p.pos6)[0:0];
        hdr.dp_3.bit_7 = (hdr.plaintext_3.value >> hdr.p.pos7)[0:0];
        hdr.dp_3.bit_8 = (hdr.plaintext_3.value >> hdr.p.pos8)[0:0];
        hdr.dp_3.bit_9 = (hdr.plaintext_3.value >> hdr.p.pos9)[0:0];
        hdr.dp_3.bit_10 = (hdr.plaintext_3.value >> hdr.p.pos10)[0:0];
        hdr.dp_3.bit_11 = (hdr.plaintext_3.value >> hdr.p.pos11)[0:0];
        hdr.dp_3.bit_12 = (hdr.plaintext_3.value >> hdr.p.pos12)[0:0];
        hdr.dp_3.bit_13 = (hdr.plaintext_3.value >> hdr.p.pos13)[0:0];
        hdr.dp_3.bit_14 = (hdr.plaintext_3.value >> hdr.p.pos14)[0:0];
        hdr.dp_3.bit_15 = (hdr.plaintext_3.value >> hdr.p.pos15)[0:0];
        hdr.dp_3.bit_16 = (hdr.plaintext_3.value >> hdr.p.pos16)[0:0];
        hdr.dp_3.bit_17 = (hdr.plaintext_3.value >> hdr.p.pos17)[0:0];
        hdr.dp_3.bit_18 = (hdr.plaintext_3.value >> hdr.p.pos18)[0:0];
        hdr.dp_3.bit_19 = (hdr.plaintext_3.value >> hdr.p.pos19)[0:0];
        hdr.dp_3.bit_20 = (hdr.plaintext_3.value >> hdr.p.pos20)[0:0];
        hdr.dp_3.bit_21 = (hdr.plaintext_3.value >> hdr.p.pos21)[0:0];
        hdr.dp_3.bit_22 = (hdr.plaintext_3.value >> hdr.p.pos22)[0:0];
        hdr.dp_3.bit_23 = (hdr.plaintext_3.value >> hdr.p.pos23)[0:0];
        hdr.dp_3.bit_24 = (hdr.plaintext_3.value >> hdr.p.pos24)[0:0];
        hdr.dp_3.bit_25 = (hdr.plaintext_3.value >> hdr.p.pos25)[0:0];
        hdr.dp_3.bit_26 = (hdr.plaintext_3.value >> hdr.p.pos26)[0:0];
        hdr.dp_3.bit_27 = (hdr.plaintext_3.value >> hdr.p.pos27)[0:0];
        hdr.dp_3.bit_28 = (hdr.plaintext_3.value >> hdr.p.pos28)[0:0];
        hdr.dp_3.bit_29 = (hdr.plaintext_3.value >> hdr.p.pos29)[0:0];
        hdr.dp_3.bit_30 = (hdr.plaintext_3.value >> hdr.p.pos30)[0:0];
        hdr.dp_3.bit_31 = (hdr.plaintext_3.value >> hdr.p.pos31)[0:0];
        hdr.dp_3.bit_32 = (hdr.plaintext_3.value >> hdr.p.pos32)[0:0];
        hdr.dp_3.bit_33 = (hdr.plaintext_3.value >> hdr.p.pos33)[0:0];
        hdr.dp_3.bit_34 = (hdr.plaintext_3.value >> hdr.p.pos34)[0:0];
        hdr.dp_3.bit_35 = (hdr.plaintext_3.value >> hdr.p.pos35)[0:0];
        hdr.dp_3.bit_36 = (hdr.plaintext_3.value >> hdr.p.pos36)[0:0];
        hdr.dp_3.bit_37 = (hdr.plaintext_3.value >> hdr.p.pos37)[0:0];
        hdr.dp_3.bit_38 = (hdr.plaintext_3.value >> hdr.p.pos38)[0:0];
        hdr.dp_3.bit_39 = (hdr.plaintext_3.value >> hdr.p.pos39)[0:0];
        hdr.dp_3.bit_40 = (hdr.plaintext_3.value >> hdr.p.pos40)[0:0];
        hdr.dp_3.bit_41 = (hdr.plaintext_3.value >> hdr.p.pos41)[0:0];
        hdr.dp_3.bit_42 = (hdr.plaintext_3.value >> hdr.p.pos42)[0:0];
        hdr.dp_3.bit_43 = (hdr.plaintext_3.value >> hdr.p.pos43)[0:0];
        hdr.dp_3.bit_44 = (hdr.plaintext_3.value >> hdr.p.pos44)[0:0];
        hdr.dp_3.bit_45 = (hdr.plaintext_3.value >> hdr.p.pos45)[0:0];
        hdr.dp_3.bit_46 = (hdr.plaintext_3.value >> hdr.p.pos46)[0:0];
        hdr.dp_3.bit_47 = (hdr.plaintext_3.value >> hdr.p.pos47)[0:0];
        hdr.dp_3.bit_48 = (hdr.plaintext_3.value >> hdr.p.pos48)[0:0];
        hdr.dp_3.bit_49 = (hdr.plaintext_3.value >> hdr.p.pos49)[0:0];
        hdr.dp_3.bit_50 = (hdr.plaintext_3.value >> hdr.p.pos50)[0:0];
        hdr.dp_3.bit_51 = (hdr.plaintext_3.value >> hdr.p.pos51)[0:0];
        hdr.dp_3.bit_52 = (hdr.plaintext_3.value >> hdr.p.pos52)[0:0];
        hdr.dp_3.bit_53 = (hdr.plaintext_3.value >> hdr.p.pos53)[0:0];
        hdr.dp_3.bit_54 = (hdr.plaintext_3.value >> hdr.p.pos54)[0:0];
        hdr.dp_3.bit_55 = (hdr.plaintext_3.value >> hdr.p.pos55)[0:0];
        hdr.dp_3.bit_56 = (hdr.plaintext_3.value >> hdr.p.pos56)[0:0];
        hdr.dp_3.bit_57 = (hdr.plaintext_3.value >> hdr.p.pos57)[0:0];
        hdr.dp_3.bit_58 = (hdr.plaintext_3.value >> hdr.p.pos58)[0:0];
        hdr.dp_3.bit_59 = (hdr.plaintext_3.value >> hdr.p.pos59)[0:0];
        hdr.dp_3.bit_60 = (hdr.plaintext_3.value >> hdr.p.pos60)[0:0];
        hdr.dp_3.bit_61 = (hdr.plaintext_3.value >> hdr.p.pos61)[0:0];
        hdr.dp_3.bit_62 = (hdr.plaintext_3.value >> hdr.p.pos62)[0:0];
        hdr.dp_3.bit_63 = (hdr.plaintext_3.value >> hdr.p.pos63)[0:0];
        hdr.dp_3.bit_64 = (hdr.plaintext_3.value >> hdr.p.pos64)[0:0];
        hdr.dp_3.bit_65 = (hdr.plaintext_3.value >> hdr.p.pos65)[0:0];
        hdr.dp_3.bit_66 = (hdr.plaintext_3.value >> hdr.p.pos66)[0:0];
        hdr.dp_3.bit_67 = (hdr.plaintext_3.value >> hdr.p.pos67)[0:0];
        hdr.dp_3.bit_68 = (hdr.plaintext_3.value >> hdr.p.pos68)[0:0];
        hdr.dp_3.bit_69 = (hdr.plaintext_3.value >> hdr.p.pos69)[0:0];
        hdr.dp_3.bit_70 = (hdr.plaintext_3.value >> hdr.p.pos70)[0:0];
        hdr.dp_3.bit_71 = (hdr.plaintext_3.value >> hdr.p.pos71)[0:0];
        hdr.dp_3.bit_72 = (hdr.plaintext_3.value >> hdr.p.pos72)[0:0];
        hdr.dp_3.bit_73 = (hdr.plaintext_3.value >> hdr.p.pos73)[0:0];
        hdr.dp_3.bit_74 = (hdr.plaintext_3.value >> hdr.p.pos74)[0:0];
        hdr.dp_3.bit_75 = (hdr.plaintext_3.value >> hdr.p.pos75)[0:0];
        hdr.dp_3.bit_76 = (hdr.plaintext_3.value >> hdr.p.pos76)[0:0];
        hdr.dp_3.bit_77 = (hdr.plaintext_3.value >> hdr.p.pos77)[0:0];
        hdr.dp_3.bit_78 = (hdr.plaintext_3.value >> hdr.p.pos78)[0:0];
        hdr.dp_3.bit_79 = (hdr.plaintext_3.value >> hdr.p.pos79)[0:0];
        hdr.dp_3.bit_80 = (hdr.plaintext_3.value >> hdr.p.pos80)[0:0];
        hdr.dp_3.bit_81 = (hdr.plaintext_3.value >> hdr.p.pos81)[0:0];
        hdr.dp_3.bit_82 = (hdr.plaintext_3.value >> hdr.p.pos82)[0:0];
        hdr.dp_3.bit_83 = (hdr.plaintext_3.value >> hdr.p.pos83)[0:0];
        hdr.dp_3.bit_84 = (hdr.plaintext_3.value >> hdr.p.pos84)[0:0];
        hdr.dp_3.bit_85 = (hdr.plaintext_3.value >> hdr.p.pos85)[0:0];
        hdr.dp_3.bit_86 = (hdr.plaintext_3.value >> hdr.p.pos86)[0:0];
        hdr.dp_3.bit_87 = (hdr.plaintext_3.value >> hdr.p.pos87)[0:0];
        hdr.dp_3.bit_88 = (hdr.plaintext_3.value >> hdr.p.pos88)[0:0];
        hdr.dp_3.bit_89 = (hdr.plaintext_3.value >> hdr.p.pos89)[0:0];
        hdr.dp_3.bit_90 = (hdr.plaintext_3.value >> hdr.p.pos90)[0:0];
        hdr.dp_3.bit_91 = (hdr.plaintext_3.value >> hdr.p.pos91)[0:0];
        hdr.dp_3.bit_92 = (hdr.plaintext_3.value >> hdr.p.pos92)[0:0];
        hdr.dp_3.bit_93 = (hdr.plaintext_3.value >> hdr.p.pos93)[0:0];
        hdr.dp_3.bit_94 = (hdr.plaintext_3.value >> hdr.p.pos94)[0:0];
        hdr.dp_3.bit_95 = (hdr.plaintext_3.value >> hdr.p.pos95)[0:0];
        hdr.dp_3.bit_96 = (hdr.plaintext_3.value >> hdr.p.pos96)[0:0];
        hdr.dp_3.bit_97 = (hdr.plaintext_3.value >> hdr.p.pos97)[0:0];
        hdr.dp_3.bit_98 = (hdr.plaintext_3.value >> hdr.p.pos98)[0:0];
        hdr.dp_3.bit_99 = (hdr.plaintext_3.value >> hdr.p.pos99)[0:0];
        hdr.dp_3.bit_100 = (hdr.plaintext_3.value >> hdr.p.pos100)[0:0];
        hdr.dp_3.bit_101 = (hdr.plaintext_3.value >> hdr.p.pos101)[0:0];
        hdr.dp_3.bit_102 = (hdr.plaintext_3.value >> hdr.p.pos102)[0:0];
        hdr.dp_3.bit_103 = (hdr.plaintext_3.value >> hdr.p.pos103)[0:0];
        hdr.dp_3.bit_104 = (hdr.plaintext_3.value >> hdr.p.pos104)[0:0];
        hdr.dp_3.bit_105 = (hdr.plaintext_3.value >> hdr.p.pos105)[0:0];
        hdr.dp_3.bit_106 = (hdr.plaintext_3.value >> hdr.p.pos106)[0:0];
        hdr.dp_3.bit_107 = (hdr.plaintext_3.value >> hdr.p.pos107)[0:0];
        hdr.dp_3.bit_108 = (hdr.plaintext_3.value >> hdr.p.pos108)[0:0];
        hdr.dp_3.bit_109 = (hdr.plaintext_3.value >> hdr.p.pos109)[0:0];
        hdr.dp_3.bit_110 = (hdr.plaintext_3.value >> hdr.p.pos110)[0:0];
        hdr.dp_3.bit_111 = (hdr.plaintext_3.value >> hdr.p.pos111)[0:0];
        hdr.dp_3.bit_112 = (hdr.plaintext_3.value >> hdr.p.pos112)[0:0];
        hdr.dp_3.bit_113 = (hdr.plaintext_3.value >> hdr.p.pos113)[0:0];
        hdr.dp_3.bit_114 = (hdr.plaintext_3.value >> hdr.p.pos114)[0:0];
        hdr.dp_3.bit_115 = (hdr.plaintext_3.value >> hdr.p.pos115)[0:0];
        hdr.dp_3.bit_116 = (hdr.plaintext_3.value >> hdr.p.pos116)[0:0];
        hdr.dp_3.bit_117 = (hdr.plaintext_3.value >> hdr.p.pos117)[0:0];
        hdr.dp_3.bit_118 = (hdr.plaintext_3.value >> hdr.p.pos118)[0:0];
        hdr.dp_3.bit_119 = (hdr.plaintext_3.value >> hdr.p.pos119)[0:0];
        hdr.dp_3.bit_120 = (hdr.plaintext_3.value >> hdr.p.pos120)[0:0];
        hdr.dp_3.bit_121 = (hdr.plaintext_3.value >> hdr.p.pos121)[0:0];
        hdr.dp_3.bit_122 = (hdr.plaintext_3.value >> hdr.p.pos122)[0:0];
        hdr.dp_3.bit_123 = (hdr.plaintext_3.value >> hdr.p.pos123)[0:0];
        hdr.dp_3.bit_124 = (hdr.plaintext_3.value >> hdr.p.pos124)[0:0];
        hdr.dp_3.bit_125 = (hdr.plaintext_3.value >> hdr.p.pos125)[0:0];
        hdr.dp_3.bit_126 = (hdr.plaintext_3.value >> hdr.p.pos126)[0:0];
        hdr.dp_3.bit_127 = (hdr.plaintext_3.value >> hdr.p.pos127)[0:0];

    }

    action inverse_permutation_ciphertext_1 () {
        bit<128> tmp;
        bit<128> tmp1 = hdr.ciphertext_1.value;
        tmp = tmp1 >> hdr.inverse_p.pos127;
        hdr.ciphertext_1.value[127:127] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos126;
        hdr.ciphertext_1.value[126:126] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos125;
        hdr.ciphertext_1.value[125:125] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos124;
        hdr.ciphertext_1.value[124:124] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos123;
        hdr.ciphertext_1.value[123:123] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos122;
        hdr.ciphertext_1.value[122:122] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos121;
        hdr.ciphertext_1.value[121:121] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos120;
        hdr.ciphertext_1.value[120:120] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos119;
        hdr.ciphertext_1.value[119:119] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos118;
        hdr.ciphertext_1.value[118:118] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos117;
        hdr.ciphertext_1.value[117:117] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos116;
        hdr.ciphertext_1.value[116:116] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos115;
        hdr.ciphertext_1.value[115:115] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos114;
        hdr.ciphertext_1.value[114:114] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos113;
        hdr.ciphertext_1.value[113:113] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos112;
        hdr.ciphertext_1.value[112:112] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos111;
        hdr.ciphertext_1.value[111:111] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos110;
        hdr.ciphertext_1.value[110:110] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos109;
        hdr.ciphertext_1.value[109:109] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos108;
        hdr.ciphertext_1.value[108:108] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos107;
        hdr.ciphertext_1.value[107:107] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos106;
        hdr.ciphertext_1.value[106:106] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos105;
        hdr.ciphertext_1.value[105:105] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos104;
        hdr.ciphertext_1.value[104:104] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos103;
        hdr.ciphertext_1.value[103:103] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos102;
        hdr.ciphertext_1.value[102:102] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos101;
        hdr.ciphertext_1.value[101:101] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos100;
        hdr.ciphertext_1.value[100:100] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos99;
        hdr.ciphertext_1.value[99:99] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos98;
        hdr.ciphertext_1.value[98:98] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos97;
        hdr.ciphertext_1.value[97:97] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos96;
        hdr.ciphertext_1.value[96:96] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos95;
        hdr.ciphertext_1.value[95:95] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos94;
        hdr.ciphertext_1.value[94:94] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos93;
        hdr.ciphertext_1.value[93:93] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos92;
        hdr.ciphertext_1.value[92:92] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos91;
        hdr.ciphertext_1.value[91:91] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos90;
        hdr.ciphertext_1.value[90:90] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos89;
        hdr.ciphertext_1.value[89:89] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos88;
        hdr.ciphertext_1.value[88:88] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos87;
        hdr.ciphertext_1.value[87:87] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos86;
        hdr.ciphertext_1.value[86:86] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos85;
        hdr.ciphertext_1.value[85:85] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos84;
        hdr.ciphertext_1.value[84:84] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos83;
        hdr.ciphertext_1.value[83:83] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos82;
        hdr.ciphertext_1.value[82:82] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos81;
        hdr.ciphertext_1.value[81:81] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos80;
        hdr.ciphertext_1.value[80:80] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos79;
        hdr.ciphertext_1.value[79:79] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos78;
        hdr.ciphertext_1.value[78:78] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos77;
        hdr.ciphertext_1.value[77:77] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos76;
        hdr.ciphertext_1.value[76:76] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos75;
        hdr.ciphertext_1.value[75:75] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos74;
        hdr.ciphertext_1.value[74:74] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos73;
        hdr.ciphertext_1.value[73:73] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos72;
        hdr.ciphertext_1.value[72:72] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos71;
        hdr.ciphertext_1.value[71:71] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos70;
        hdr.ciphertext_1.value[70:70] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos69;
        hdr.ciphertext_1.value[69:69] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos68;
        hdr.ciphertext_1.value[68:68] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos67;
        hdr.ciphertext_1.value[67:67] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos66;
        hdr.ciphertext_1.value[66:66] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos65;
        hdr.ciphertext_1.value[65:65] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos64;
        hdr.ciphertext_1.value[64:64] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos63;
        hdr.ciphertext_1.value[63:63] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos62;
        hdr.ciphertext_1.value[62:62] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos61;
        hdr.ciphertext_1.value[61:61] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos60;
        hdr.ciphertext_1.value[60:60] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos59;
        hdr.ciphertext_1.value[59:59] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos58;
        hdr.ciphertext_1.value[58:58] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos57;
        hdr.ciphertext_1.value[57:57] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos56;
        hdr.ciphertext_1.value[56:56] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos55;
        hdr.ciphertext_1.value[55:55] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos54;
        hdr.ciphertext_1.value[54:54] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos53;
        hdr.ciphertext_1.value[53:53] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos52;
        hdr.ciphertext_1.value[52:52] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos51;
        hdr.ciphertext_1.value[51:51] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos50;
        hdr.ciphertext_1.value[50:50] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos49;
        hdr.ciphertext_1.value[49:49] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos48;
        hdr.ciphertext_1.value[48:48] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos47;
        hdr.ciphertext_1.value[47:47] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos46;
        hdr.ciphertext_1.value[46:46] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos45;
        hdr.ciphertext_1.value[45:45] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos44;
        hdr.ciphertext_1.value[44:44] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos43;
        hdr.ciphertext_1.value[43:43] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos42;
        hdr.ciphertext_1.value[42:42] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos41;
        hdr.ciphertext_1.value[41:41] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos40;
        hdr.ciphertext_1.value[40:40] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos39;
        hdr.ciphertext_1.value[39:39] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos38;
        hdr.ciphertext_1.value[38:38] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos37;
        hdr.ciphertext_1.value[37:37] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos36;
        hdr.ciphertext_1.value[36:36] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos35;
        hdr.ciphertext_1.value[35:35] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos34;
        hdr.ciphertext_1.value[34:34] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos33;
        hdr.ciphertext_1.value[33:33] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos32;
        hdr.ciphertext_1.value[32:32] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos31;
        hdr.ciphertext_1.value[31:31] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos30;
        hdr.ciphertext_1.value[30:30] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos29;
        hdr.ciphertext_1.value[29:29] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos28;
        hdr.ciphertext_1.value[28:28] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos27;
        hdr.ciphertext_1.value[27:27] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos26;
        hdr.ciphertext_1.value[26:26] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos25;
        hdr.ciphertext_1.value[25:25] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos24;
        hdr.ciphertext_1.value[24:24] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos23;
        hdr.ciphertext_1.value[23:23] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos22;
        hdr.ciphertext_1.value[22:22] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos21;
        hdr.ciphertext_1.value[21:21] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos20;
        hdr.ciphertext_1.value[20:20] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos19;
        hdr.ciphertext_1.value[19:19] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos18;
        hdr.ciphertext_1.value[18:18] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos17;
        hdr.ciphertext_1.value[17:17] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos16;
        hdr.ciphertext_1.value[16:16] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos15;
        hdr.ciphertext_1.value[15:15] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos14;
        hdr.ciphertext_1.value[14:14] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos13;
        hdr.ciphertext_1.value[13:13] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos12;
        hdr.ciphertext_1.value[12:12] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos11;
        hdr.ciphertext_1.value[11:11] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos10;
        hdr.ciphertext_1.value[10:10] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos9;
        hdr.ciphertext_1.value[9:9] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos8;
        hdr.ciphertext_1.value[8:8] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos7;
        hdr.ciphertext_1.value[7:7] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos6;
        hdr.ciphertext_1.value[6:6] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos5;
        hdr.ciphertext_1.value[5:5] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos4;
        hdr.ciphertext_1.value[4:4] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos3;
        hdr.ciphertext_1.value[3:3] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos2;
        hdr.ciphertext_1.value[2:2] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos1;
        hdr.ciphertext_1.value[1:1] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos0;
        hdr.ciphertext_1.value[0:0] = tmp[0:0];
    }

    action inverse_permutation_ciphertext_2 () {
        bit<128> tmp;
        bit<128> tmp1 = hdr.ciphertext_2.value;
        tmp = tmp1 >> hdr.inverse_p.pos127;
        hdr.ciphertext_2.value[127:127] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos126;
        hdr.ciphertext_2.value[126:126] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos125;
        hdr.ciphertext_2.value[125:125] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos124;
        hdr.ciphertext_2.value[124:124] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos123;
        hdr.ciphertext_2.value[123:123] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos122;
        hdr.ciphertext_2.value[122:122] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos121;
        hdr.ciphertext_2.value[121:121] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos120;
        hdr.ciphertext_2.value[120:120] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos119;
        hdr.ciphertext_2.value[119:119] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos118;
        hdr.ciphertext_2.value[118:118] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos117;
        hdr.ciphertext_2.value[117:117] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos116;
        hdr.ciphertext_2.value[116:116] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos115;
        hdr.ciphertext_2.value[115:115] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos114;
        hdr.ciphertext_2.value[114:114] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos113;
        hdr.ciphertext_2.value[113:113] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos112;
        hdr.ciphertext_2.value[112:112] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos111;
        hdr.ciphertext_2.value[111:111] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos110;
        hdr.ciphertext_2.value[110:110] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos109;
        hdr.ciphertext_2.value[109:109] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos108;
        hdr.ciphertext_2.value[108:108] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos107;
        hdr.ciphertext_2.value[107:107] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos106;
        hdr.ciphertext_2.value[106:106] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos105;
        hdr.ciphertext_2.value[105:105] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos104;
        hdr.ciphertext_2.value[104:104] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos103;
        hdr.ciphertext_2.value[103:103] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos102;
        hdr.ciphertext_2.value[102:102] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos101;
        hdr.ciphertext_2.value[101:101] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos100;
        hdr.ciphertext_2.value[100:100] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos99;
        hdr.ciphertext_2.value[99:99] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos98;
        hdr.ciphertext_2.value[98:98] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos97;
        hdr.ciphertext_2.value[97:97] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos96;
        hdr.ciphertext_2.value[96:96] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos95;
        hdr.ciphertext_2.value[95:95] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos94;
        hdr.ciphertext_2.value[94:94] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos93;
        hdr.ciphertext_2.value[93:93] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos92;
        hdr.ciphertext_2.value[92:92] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos91;
        hdr.ciphertext_2.value[91:91] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos90;
        hdr.ciphertext_2.value[90:90] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos89;
        hdr.ciphertext_2.value[89:89] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos88;
        hdr.ciphertext_2.value[88:88] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos87;
        hdr.ciphertext_2.value[87:87] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos86;
        hdr.ciphertext_2.value[86:86] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos85;
        hdr.ciphertext_2.value[85:85] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos84;
        hdr.ciphertext_2.value[84:84] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos83;
        hdr.ciphertext_2.value[83:83] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos82;
        hdr.ciphertext_2.value[82:82] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos81;
        hdr.ciphertext_2.value[81:81] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos80;
        hdr.ciphertext_2.value[80:80] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos79;
        hdr.ciphertext_2.value[79:79] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos78;
        hdr.ciphertext_2.value[78:78] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos77;
        hdr.ciphertext_2.value[77:77] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos76;
        hdr.ciphertext_2.value[76:76] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos75;
        hdr.ciphertext_2.value[75:75] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos74;
        hdr.ciphertext_2.value[74:74] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos73;
        hdr.ciphertext_2.value[73:73] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos72;
        hdr.ciphertext_2.value[72:72] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos71;
        hdr.ciphertext_2.value[71:71] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos70;
        hdr.ciphertext_2.value[70:70] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos69;
        hdr.ciphertext_2.value[69:69] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos68;
        hdr.ciphertext_2.value[68:68] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos67;
        hdr.ciphertext_2.value[67:67] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos66;
        hdr.ciphertext_2.value[66:66] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos65;
        hdr.ciphertext_2.value[65:65] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos64;
        hdr.ciphertext_2.value[64:64] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos63;
        hdr.ciphertext_2.value[63:63] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos62;
        hdr.ciphertext_2.value[62:62] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos61;
        hdr.ciphertext_2.value[61:61] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos60;
        hdr.ciphertext_2.value[60:60] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos59;
        hdr.ciphertext_2.value[59:59] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos58;
        hdr.ciphertext_2.value[58:58] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos57;
        hdr.ciphertext_2.value[57:57] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos56;
        hdr.ciphertext_2.value[56:56] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos55;
        hdr.ciphertext_2.value[55:55] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos54;
        hdr.ciphertext_2.value[54:54] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos53;
        hdr.ciphertext_2.value[53:53] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos52;
        hdr.ciphertext_2.value[52:52] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos51;
        hdr.ciphertext_2.value[51:51] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos50;
        hdr.ciphertext_2.value[50:50] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos49;
        hdr.ciphertext_2.value[49:49] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos48;
        hdr.ciphertext_2.value[48:48] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos47;
        hdr.ciphertext_2.value[47:47] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos46;
        hdr.ciphertext_2.value[46:46] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos45;
        hdr.ciphertext_2.value[45:45] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos44;
        hdr.ciphertext_2.value[44:44] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos43;
        hdr.ciphertext_2.value[43:43] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos42;
        hdr.ciphertext_2.value[42:42] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos41;
        hdr.ciphertext_2.value[41:41] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos40;
        hdr.ciphertext_2.value[40:40] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos39;
        hdr.ciphertext_2.value[39:39] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos38;
        hdr.ciphertext_2.value[38:38] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos37;
        hdr.ciphertext_2.value[37:37] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos36;
        hdr.ciphertext_2.value[36:36] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos35;
        hdr.ciphertext_2.value[35:35] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos34;
        hdr.ciphertext_2.value[34:34] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos33;
        hdr.ciphertext_2.value[33:33] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos32;
        hdr.ciphertext_2.value[32:32] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos31;
        hdr.ciphertext_2.value[31:31] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos30;
        hdr.ciphertext_2.value[30:30] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos29;
        hdr.ciphertext_2.value[29:29] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos28;
        hdr.ciphertext_2.value[28:28] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos27;
        hdr.ciphertext_2.value[27:27] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos26;
        hdr.ciphertext_2.value[26:26] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos25;
        hdr.ciphertext_2.value[25:25] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos24;
        hdr.ciphertext_2.value[24:24] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos23;
        hdr.ciphertext_2.value[23:23] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos22;
        hdr.ciphertext_2.value[22:22] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos21;
        hdr.ciphertext_2.value[21:21] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos20;
        hdr.ciphertext_2.value[20:20] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos19;
        hdr.ciphertext_2.value[19:19] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos18;
        hdr.ciphertext_2.value[18:18] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos17;
        hdr.ciphertext_2.value[17:17] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos16;
        hdr.ciphertext_2.value[16:16] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos15;
        hdr.ciphertext_2.value[15:15] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos14;
        hdr.ciphertext_2.value[14:14] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos13;
        hdr.ciphertext_2.value[13:13] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos12;
        hdr.ciphertext_2.value[12:12] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos11;
        hdr.ciphertext_2.value[11:11] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos10;
        hdr.ciphertext_2.value[10:10] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos9;
        hdr.ciphertext_2.value[9:9] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos8;
        hdr.ciphertext_2.value[8:8] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos7;
        hdr.ciphertext_2.value[7:7] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos6;
        hdr.ciphertext_2.value[6:6] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos5;
        hdr.ciphertext_2.value[5:5] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos4;
        hdr.ciphertext_2.value[4:4] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos3;
        hdr.ciphertext_2.value[3:3] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos2;
        hdr.ciphertext_2.value[2:2] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos1;
        hdr.ciphertext_2.value[1:1] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos0;
        hdr.ciphertext_2.value[0:0] = tmp[0:0];
    }

    action inverse_permutation_ciphertext_3 () {
        bit<128> tmp;
        bit<128> tmp1 = hdr.ciphertext_3.value;
        tmp = tmp1 >> hdr.inverse_p.pos127;
        hdr.ciphertext_3.value[127:127] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos126;
        hdr.ciphertext_3.value[126:126] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos125;
        hdr.ciphertext_3.value[125:125] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos124;
        hdr.ciphertext_3.value[124:124] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos123;
        hdr.ciphertext_3.value[123:123] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos122;
        hdr.ciphertext_3.value[122:122] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos121;
        hdr.ciphertext_3.value[121:121] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos120;
        hdr.ciphertext_3.value[120:120] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos119;
        hdr.ciphertext_3.value[119:119] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos118;
        hdr.ciphertext_3.value[118:118] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos117;
        hdr.ciphertext_3.value[117:117] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos116;
        hdr.ciphertext_3.value[116:116] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos115;
        hdr.ciphertext_3.value[115:115] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos114;
        hdr.ciphertext_3.value[114:114] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos113;
        hdr.ciphertext_3.value[113:113] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos112;
        hdr.ciphertext_3.value[112:112] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos111;
        hdr.ciphertext_3.value[111:111] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos110;
        hdr.ciphertext_3.value[110:110] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos109;
        hdr.ciphertext_3.value[109:109] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos108;
        hdr.ciphertext_3.value[108:108] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos107;
        hdr.ciphertext_3.value[107:107] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos106;
        hdr.ciphertext_3.value[106:106] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos105;
        hdr.ciphertext_3.value[105:105] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos104;
        hdr.ciphertext_3.value[104:104] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos103;
        hdr.ciphertext_3.value[103:103] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos102;
        hdr.ciphertext_3.value[102:102] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos101;
        hdr.ciphertext_3.value[101:101] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos100;
        hdr.ciphertext_3.value[100:100] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos99;
        hdr.ciphertext_3.value[99:99] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos98;
        hdr.ciphertext_3.value[98:98] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos97;
        hdr.ciphertext_3.value[97:97] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos96;
        hdr.ciphertext_3.value[96:96] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos95;
        hdr.ciphertext_3.value[95:95] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos94;
        hdr.ciphertext_3.value[94:94] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos93;
        hdr.ciphertext_3.value[93:93] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos92;
        hdr.ciphertext_3.value[92:92] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos91;
        hdr.ciphertext_3.value[91:91] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos90;
        hdr.ciphertext_3.value[90:90] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos89;
        hdr.ciphertext_3.value[89:89] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos88;
        hdr.ciphertext_3.value[88:88] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos87;
        hdr.ciphertext_3.value[87:87] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos86;
        hdr.ciphertext_3.value[86:86] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos85;
        hdr.ciphertext_3.value[85:85] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos84;
        hdr.ciphertext_3.value[84:84] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos83;
        hdr.ciphertext_3.value[83:83] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos82;
        hdr.ciphertext_3.value[82:82] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos81;
        hdr.ciphertext_3.value[81:81] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos80;
        hdr.ciphertext_3.value[80:80] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos79;
        hdr.ciphertext_3.value[79:79] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos78;
        hdr.ciphertext_3.value[78:78] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos77;
        hdr.ciphertext_3.value[77:77] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos76;
        hdr.ciphertext_3.value[76:76] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos75;
        hdr.ciphertext_3.value[75:75] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos74;
        hdr.ciphertext_3.value[74:74] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos73;
        hdr.ciphertext_3.value[73:73] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos72;
        hdr.ciphertext_3.value[72:72] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos71;
        hdr.ciphertext_3.value[71:71] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos70;
        hdr.ciphertext_3.value[70:70] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos69;
        hdr.ciphertext_3.value[69:69] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos68;
        hdr.ciphertext_3.value[68:68] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos67;
        hdr.ciphertext_3.value[67:67] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos66;
        hdr.ciphertext_3.value[66:66] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos65;
        hdr.ciphertext_3.value[65:65] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos64;
        hdr.ciphertext_3.value[64:64] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos63;
        hdr.ciphertext_3.value[63:63] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos62;
        hdr.ciphertext_3.value[62:62] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos61;
        hdr.ciphertext_3.value[61:61] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos60;
        hdr.ciphertext_3.value[60:60] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos59;
        hdr.ciphertext_3.value[59:59] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos58;
        hdr.ciphertext_3.value[58:58] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos57;
        hdr.ciphertext_3.value[57:57] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos56;
        hdr.ciphertext_3.value[56:56] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos55;
        hdr.ciphertext_3.value[55:55] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos54;
        hdr.ciphertext_3.value[54:54] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos53;
        hdr.ciphertext_3.value[53:53] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos52;
        hdr.ciphertext_3.value[52:52] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos51;
        hdr.ciphertext_3.value[51:51] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos50;
        hdr.ciphertext_3.value[50:50] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos49;
        hdr.ciphertext_3.value[49:49] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos48;
        hdr.ciphertext_3.value[48:48] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos47;
        hdr.ciphertext_3.value[47:47] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos46;
        hdr.ciphertext_3.value[46:46] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos45;
        hdr.ciphertext_3.value[45:45] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos44;
        hdr.ciphertext_3.value[44:44] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos43;
        hdr.ciphertext_3.value[43:43] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos42;
        hdr.ciphertext_3.value[42:42] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos41;
        hdr.ciphertext_3.value[41:41] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos40;
        hdr.ciphertext_3.value[40:40] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos39;
        hdr.ciphertext_3.value[39:39] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos38;
        hdr.ciphertext_3.value[38:38] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos37;
        hdr.ciphertext_3.value[37:37] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos36;
        hdr.ciphertext_3.value[36:36] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos35;
        hdr.ciphertext_3.value[35:35] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos34;
        hdr.ciphertext_3.value[34:34] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos33;
        hdr.ciphertext_3.value[33:33] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos32;
        hdr.ciphertext_3.value[32:32] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos31;
        hdr.ciphertext_3.value[31:31] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos30;
        hdr.ciphertext_3.value[30:30] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos29;
        hdr.ciphertext_3.value[29:29] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos28;
        hdr.ciphertext_3.value[28:28] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos27;
        hdr.ciphertext_3.value[27:27] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos26;
        hdr.ciphertext_3.value[26:26] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos25;
        hdr.ciphertext_3.value[25:25] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos24;
        hdr.ciphertext_3.value[24:24] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos23;
        hdr.ciphertext_3.value[23:23] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos22;
        hdr.ciphertext_3.value[22:22] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos21;
        hdr.ciphertext_3.value[21:21] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos20;
        hdr.ciphertext_3.value[20:20] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos19;
        hdr.ciphertext_3.value[19:19] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos18;
        hdr.ciphertext_3.value[18:18] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos17;
        hdr.ciphertext_3.value[17:17] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos16;
        hdr.ciphertext_3.value[16:16] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos15;
        hdr.ciphertext_3.value[15:15] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos14;
        hdr.ciphertext_3.value[14:14] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos13;
        hdr.ciphertext_3.value[13:13] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos12;
        hdr.ciphertext_3.value[12:12] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos11;
        hdr.ciphertext_3.value[11:11] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos10;
        hdr.ciphertext_3.value[10:10] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos9;
        hdr.ciphertext_3.value[9:9] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos8;
        hdr.ciphertext_3.value[8:8] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos7;
        hdr.ciphertext_3.value[7:7] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos6;
        hdr.ciphertext_3.value[6:6] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos5;
        hdr.ciphertext_3.value[5:5] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos4;
        hdr.ciphertext_3.value[4:4] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos3;
        hdr.ciphertext_3.value[3:3] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos2;
        hdr.ciphertext_3.value[2:2] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos1;
        hdr.ciphertext_3.value[1:1] = tmp[0:0];
        tmp = tmp1 >> hdr.inverse_p.pos0;
        hdr.ciphertext_3.value[0:0] = tmp[0:0];

    }

    action read_encryption_key (bit<128> k) {
        hdr.encryption_key.setValid();
        hdr.encryption_key.k = k;
    }

    action read_permutation (bit<8> pos0, bit<8> pos1, bit<8> pos2, bit<8> pos3,
        bit<8> pos4, bit<8> pos5, bit<8> pos6, bit<8> pos7, bit<8> pos8, bit<8> pos9, bit<8> pos10,
        bit<8> pos11, bit<8> pos12, bit<8> pos13, bit<8> pos14, bit<8> pos15, bit<8> pos16,
        bit<8> pos17, bit<8> pos18, bit<8> pos19, bit<8> pos20, bit<8> pos21, bit<8> pos22,
        bit<8> pos23, bit<8> pos24, bit<8> pos25, bit<8> pos26, bit<8> pos27, bit<8> pos28,
        bit<8> pos29, bit<8> pos30, bit<8> pos31, bit<8> pos32, bit<8> pos33, bit<8> pos34,
        bit<8> pos35, bit<8> pos36, bit<8> pos37, bit<8> pos38, bit<8> pos39, bit<8> pos40,
        bit<8> pos41, bit<8> pos42, bit<8> pos43, bit<8> pos44, bit<8> pos45, bit<8> pos46,
        bit<8> pos47, bit<8> pos48, bit<8> pos49, bit<8> pos50, bit<8> pos51, bit<8> pos52,
        bit<8> pos53, bit<8> pos54, bit<8> pos55, bit<8> pos56, bit<8> pos57, bit<8> pos58,
        bit<8> pos59, bit<8> pos60, bit<8> pos61, bit<8> pos62, bit<8> pos63, bit<8> pos64,
        bit<8> pos65, bit<8> pos66, bit<8> pos67, bit<8> pos68, bit<8> pos69, bit<8> pos70,
        bit<8> pos71, bit<8> pos72, bit<8> pos73, bit<8> pos74, bit<8> pos75, bit<8> pos76,
        bit<8> pos77, bit<8> pos78, bit<8> pos79, bit<8> pos80, bit<8> pos81, bit<8> pos82,
        bit<8> pos83, bit<8> pos84, bit<8> pos85, bit<8> pos86, bit<8> pos87, bit<8> pos88,
        bit<8> pos89, bit<8> pos90, bit<8> pos91, bit<8> pos92, bit<8> pos93, bit<8> pos94,
        bit<8> pos95, bit<8> pos96, bit<8> pos97, bit<8> pos98, bit<8> pos99, bit<8> pos100,
        bit<8> pos101, bit<8> pos102, bit<8> pos103, bit<8> pos104, bit<8> pos105, bit<8> pos106,
        bit<8> pos107, bit<8> pos108, bit<8> pos109, bit<8> pos110, bit<8> pos111, bit<8> pos112,
        bit<8> pos113, bit<8> pos114, bit<8> pos115, bit<8> pos116, bit<8> pos117, bit<8> pos118,
        bit<8> pos119, bit<8> pos120, bit<8> pos121, bit<8> pos122, bit<8> pos123, bit<8> pos124,
        bit<8> pos125, bit<8> pos126, bit<8> pos127) {


        hdr.p.setValid();

        hdr.p.pos0 = pos0;
        hdr.p.pos1 = pos1;
        hdr.p.pos2 = pos2;
        hdr.p.pos3 = pos3;
        hdr.p.pos4 = pos4;
        hdr.p.pos5 = pos5;
        hdr.p.pos6 = pos6;
        hdr.p.pos7 = pos7;
        hdr.p.pos8 = pos8;
        hdr.p.pos9 = pos9;
        hdr.p.pos10 = pos10;
        hdr.p.pos11 = pos11;
        hdr.p.pos12 = pos12;
        hdr.p.pos13 = pos13;
        hdr.p.pos14 = pos14;
        hdr.p.pos15 = pos15;
        hdr.p.pos16 = pos16;
        hdr.p.pos17 = pos17;
        hdr.p.pos18 = pos18;
        hdr.p.pos19 = pos19;
        hdr.p.pos20 = pos20;
        hdr.p.pos21 = pos21;
        hdr.p.pos22 = pos22;
        hdr.p.pos23 = pos23;
        hdr.p.pos24 = pos24;
        hdr.p.pos25 = pos25;
        hdr.p.pos26 = pos26;
        hdr.p.pos27 = pos27;
        hdr.p.pos28 = pos28;
        hdr.p.pos29 = pos29;
        hdr.p.pos30 = pos30;
        hdr.p.pos31 = pos31;
        hdr.p.pos32 = pos32;
        hdr.p.pos33 = pos33;
        hdr.p.pos34 = pos34;
        hdr.p.pos35 = pos35;
        hdr.p.pos36 = pos36;
        hdr.p.pos37 = pos37;
        hdr.p.pos38 = pos38;
        hdr.p.pos39 = pos39;
        hdr.p.pos40 = pos40;
        hdr.p.pos41 = pos41;
        hdr.p.pos42 = pos42;
        hdr.p.pos43 = pos43;
        hdr.p.pos44 = pos44;
        hdr.p.pos45 = pos45;
        hdr.p.pos46 = pos46;
        hdr.p.pos47 = pos47;
        hdr.p.pos48 = pos48;
        hdr.p.pos49 = pos49;
        hdr.p.pos50 = pos50;
        hdr.p.pos51 = pos51;
        hdr.p.pos52 = pos52;
        hdr.p.pos53 = pos53;
        hdr.p.pos54 = pos54;
        hdr.p.pos55 = pos55;
        hdr.p.pos56 = pos56;
        hdr.p.pos57 = pos57;
        hdr.p.pos58 = pos58;
        hdr.p.pos59 = pos59;
        hdr.p.pos60 = pos60;
        hdr.p.pos61 = pos61;
        hdr.p.pos62 = pos62;
        hdr.p.pos63 = pos63;
        hdr.p.pos64 = pos64;
        hdr.p.pos65 = pos65;
        hdr.p.pos66 = pos66;
        hdr.p.pos67 = pos67;
        hdr.p.pos68 = pos68;
        hdr.p.pos69 = pos69;
        hdr.p.pos70 = pos70;
        hdr.p.pos71 = pos71;
        hdr.p.pos72 = pos72;
        hdr.p.pos73 = pos73;
        hdr.p.pos74 = pos74;
        hdr.p.pos75 = pos75;
        hdr.p.pos76 = pos76;
        hdr.p.pos77 = pos77;
        hdr.p.pos78 = pos78;
        hdr.p.pos79 = pos79;
        hdr.p.pos80 = pos80;
        hdr.p.pos81 = pos81;
        hdr.p.pos82 = pos82;
        hdr.p.pos83 = pos83;
        hdr.p.pos84 = pos84;
        hdr.p.pos85 = pos85;
        hdr.p.pos86 = pos86;
        hdr.p.pos87 = pos87;
        hdr.p.pos88 = pos88;
        hdr.p.pos89 = pos89;
        hdr.p.pos90 = pos90;
        hdr.p.pos91 = pos91;
        hdr.p.pos92 = pos92;
        hdr.p.pos93 = pos93;
        hdr.p.pos94 = pos94;
        hdr.p.pos95 = pos95;
        hdr.p.pos96 = pos96;
        hdr.p.pos97 = pos97;
        hdr.p.pos98 = pos98;
        hdr.p.pos99 = pos99;
        hdr.p.pos100 = pos100;
        hdr.p.pos101 = pos101;
        hdr.p.pos102 = pos102;
        hdr.p.pos103 = pos103;
        hdr.p.pos104 = pos104;
        hdr.p.pos105 = pos105;
        hdr.p.pos106 = pos106;
        hdr.p.pos107 = pos107;
        hdr.p.pos108 = pos108;
        hdr.p.pos109 = pos109;
        hdr.p.pos110 = pos110;
        hdr.p.pos111 = pos111;
        hdr.p.pos112 = pos112;
        hdr.p.pos113 = pos113;
        hdr.p.pos114 = pos114;
        hdr.p.pos115 = pos115;
        hdr.p.pos116 = pos116;
        hdr.p.pos117 = pos117;
        hdr.p.pos118 = pos118;
        hdr.p.pos119 = pos119;
        hdr.p.pos120 = pos120;
        hdr.p.pos121 = pos121;
        hdr.p.pos122 = pos122;
        hdr.p.pos123 = pos123;
        hdr.p.pos124 = pos124;
        hdr.p.pos125 = pos125;
        hdr.p.pos126 = pos126;
        hdr.p.pos127 = pos127;

    }

    action read_inverse_permutation (bit<8> pos0, bit<8> pos1, bit<8> pos2, bit<8> pos3,
        bit<8> pos4, bit<8> pos5, bit<8> pos6, bit<8> pos7, bit<8> pos8, bit<8> pos9, bit<8> pos10,
        bit<8> pos11, bit<8> pos12, bit<8> pos13, bit<8> pos14, bit<8> pos15, bit<8> pos16,
        bit<8> pos17, bit<8> pos18, bit<8> pos19, bit<8> pos20, bit<8> pos21, bit<8> pos22,
        bit<8> pos23, bit<8> pos24, bit<8> pos25, bit<8> pos26, bit<8> pos27, bit<8> pos28,
        bit<8> pos29, bit<8> pos30, bit<8> pos31, bit<8> pos32, bit<8> pos33, bit<8> pos34,
        bit<8> pos35, bit<8> pos36, bit<8> pos37, bit<8> pos38, bit<8> pos39, bit<8> pos40,
        bit<8> pos41, bit<8> pos42, bit<8> pos43, bit<8> pos44, bit<8> pos45, bit<8> pos46,
        bit<8> pos47, bit<8> pos48, bit<8> pos49, bit<8> pos50, bit<8> pos51, bit<8> pos52,
        bit<8> pos53, bit<8> pos54, bit<8> pos55, bit<8> pos56, bit<8> pos57, bit<8> pos58,
        bit<8> pos59, bit<8> pos60, bit<8> pos61, bit<8> pos62, bit<8> pos63, bit<8> pos64,
        bit<8> pos65, bit<8> pos66, bit<8> pos67, bit<8> pos68, bit<8> pos69, bit<8> pos70,
        bit<8> pos71, bit<8> pos72, bit<8> pos73, bit<8> pos74, bit<8> pos75, bit<8> pos76,
        bit<8> pos77, bit<8> pos78, bit<8> pos79, bit<8> pos80, bit<8> pos81, bit<8> pos82,
        bit<8> pos83, bit<8> pos84, bit<8> pos85, bit<8> pos86, bit<8> pos87, bit<8> pos88,
        bit<8> pos89, bit<8> pos90, bit<8> pos91, bit<8> pos92, bit<8> pos93, bit<8> pos94,
        bit<8> pos95, bit<8> pos96, bit<8> pos97, bit<8> pos98, bit<8> pos99, bit<8> pos100,
        bit<8> pos101, bit<8> pos102, bit<8> pos103, bit<8> pos104, bit<8> pos105, bit<8> pos106,
        bit<8> pos107, bit<8> pos108, bit<8> pos109, bit<8> pos110, bit<8> pos111, bit<8> pos112,
        bit<8> pos113, bit<8> pos114, bit<8> pos115, bit<8> pos116, bit<8> pos117, bit<8> pos118,
        bit<8> pos119, bit<8> pos120, bit<8> pos121, bit<8> pos122, bit<8> pos123, bit<8> pos124,
        bit<8> pos125, bit<8> pos126, bit<8> pos127) {

        hdr.inverse_p.setValid();

        hdr.inverse_p.pos0 = pos0;
        hdr.inverse_p.pos1 = pos1;
        hdr.inverse_p.pos2 = pos2;
        hdr.inverse_p.pos3 = pos3;
        hdr.inverse_p.pos4 = pos4;
        hdr.inverse_p.pos5 = pos5;
        hdr.inverse_p.pos6 = pos6;
        hdr.inverse_p.pos7 = pos7;
        hdr.inverse_p.pos8 = pos8;
        hdr.inverse_p.pos9 = pos9;
        hdr.inverse_p.pos10 = pos10;
        hdr.inverse_p.pos11 = pos11;
        hdr.inverse_p.pos12 = pos12;
        hdr.inverse_p.pos13 = pos13;
        hdr.inverse_p.pos14 = pos14;
        hdr.inverse_p.pos15 = pos15;
        hdr.inverse_p.pos16 = pos16;
        hdr.inverse_p.pos17 = pos17;
        hdr.inverse_p.pos18 = pos18;
        hdr.inverse_p.pos19 = pos19;
        hdr.inverse_p.pos20 = pos20;
        hdr.inverse_p.pos21 = pos21;
        hdr.inverse_p.pos22 = pos22;
        hdr.inverse_p.pos23 = pos23;
        hdr.inverse_p.pos24 = pos24;
        hdr.inverse_p.pos25 = pos25;
        hdr.inverse_p.pos26 = pos26;
        hdr.inverse_p.pos27 = pos27;
        hdr.inverse_p.pos28 = pos28;
        hdr.inverse_p.pos29 = pos29;
        hdr.inverse_p.pos30 = pos30;
        hdr.inverse_p.pos31 = pos31;
        hdr.inverse_p.pos32 = pos32;
        hdr.inverse_p.pos33 = pos33;
        hdr.inverse_p.pos34 = pos34;
        hdr.inverse_p.pos35 = pos35;
        hdr.inverse_p.pos36 = pos36;
        hdr.inverse_p.pos37 = pos37;
        hdr.inverse_p.pos38 = pos38;
        hdr.inverse_p.pos39 = pos39;
        hdr.inverse_p.pos40 = pos40;
        hdr.inverse_p.pos41 = pos41;
        hdr.inverse_p.pos42 = pos42;
        hdr.inverse_p.pos43 = pos43;
        hdr.inverse_p.pos44 = pos44;
        hdr.inverse_p.pos45 = pos45;
        hdr.inverse_p.pos46 = pos46;
        hdr.inverse_p.pos47 = pos47;
        hdr.inverse_p.pos48 = pos48;
        hdr.inverse_p.pos49 = pos49;
        hdr.inverse_p.pos50 = pos50;
        hdr.inverse_p.pos51 = pos51;
        hdr.inverse_p.pos52 = pos52;
        hdr.inverse_p.pos53 = pos53;
        hdr.inverse_p.pos54 = pos54;
        hdr.inverse_p.pos55 = pos55;
        hdr.inverse_p.pos56 = pos56;
        hdr.inverse_p.pos57 = pos57;
        hdr.inverse_p.pos58 = pos58;
        hdr.inverse_p.pos59 = pos59;
        hdr.inverse_p.pos60 = pos60;
        hdr.inverse_p.pos61 = pos61;
        hdr.inverse_p.pos62 = pos62;
        hdr.inverse_p.pos63 = pos63;
        hdr.inverse_p.pos64 = pos64;
        hdr.inverse_p.pos65 = pos65;
        hdr.inverse_p.pos66 = pos66;
        hdr.inverse_p.pos67 = pos67;
        hdr.inverse_p.pos68 = pos68;
        hdr.inverse_p.pos69 = pos69;
        hdr.inverse_p.pos70 = pos70;
        hdr.inverse_p.pos71 = pos71;
        hdr.inverse_p.pos72 = pos72;
        hdr.inverse_p.pos73 = pos73;
        hdr.inverse_p.pos74 = pos74;
        hdr.inverse_p.pos75 = pos75;
        hdr.inverse_p.pos76 = pos76;
        hdr.inverse_p.pos77 = pos77;
        hdr.inverse_p.pos78 = pos78;
        hdr.inverse_p.pos79 = pos79;
        hdr.inverse_p.pos80 = pos80;
        hdr.inverse_p.pos81 = pos81;
        hdr.inverse_p.pos82 = pos82;
        hdr.inverse_p.pos83 = pos83;
        hdr.inverse_p.pos84 = pos84;
        hdr.inverse_p.pos85 = pos85;
        hdr.inverse_p.pos86 = pos86;
        hdr.inverse_p.pos87 = pos87;
        hdr.inverse_p.pos88 = pos88;
        hdr.inverse_p.pos89 = pos89;
        hdr.inverse_p.pos90 = pos90;
        hdr.inverse_p.pos91 = pos91;
        hdr.inverse_p.pos92 = pos92;
        hdr.inverse_p.pos93 = pos93;
        hdr.inverse_p.pos94 = pos94;
        hdr.inverse_p.pos95 = pos95;
        hdr.inverse_p.pos96 = pos96;
        hdr.inverse_p.pos97 = pos97;
        hdr.inverse_p.pos98 = pos98;
        hdr.inverse_p.pos99 = pos99;
        hdr.inverse_p.pos100 = pos100;
        hdr.inverse_p.pos101 = pos101;
        hdr.inverse_p.pos102 = pos102;
        hdr.inverse_p.pos103 = pos103;
        hdr.inverse_p.pos104 = pos104;
        hdr.inverse_p.pos105 = pos105;
        hdr.inverse_p.pos106 = pos106;
        hdr.inverse_p.pos107 = pos107;
        hdr.inverse_p.pos108 = pos108;
        hdr.inverse_p.pos109 = pos109;
        hdr.inverse_p.pos110 = pos110;
        hdr.inverse_p.pos111 = pos111;
        hdr.inverse_p.pos112 = pos112;
        hdr.inverse_p.pos113 = pos113;
        hdr.inverse_p.pos114 = pos114;
        hdr.inverse_p.pos115 = pos115;
        hdr.inverse_p.pos116 = pos116;
        hdr.inverse_p.pos117 = pos117;
        hdr.inverse_p.pos118 = pos118;
        hdr.inverse_p.pos119 = pos119;
        hdr.inverse_p.pos120 = pos120;
        hdr.inverse_p.pos121 = pos121;
        hdr.inverse_p.pos122 = pos122;
        hdr.inverse_p.pos123 = pos123;
        hdr.inverse_p.pos124 = pos124;
        hdr.inverse_p.pos125 = pos125;
        hdr.inverse_p.pos126 = pos126;
        hdr.inverse_p.pos127 = pos127;

    }

    action from_bit_to_byte() {
        hdr.plaintext_1.value = hdr.dp_1.bit_0++
        hdr.dp_1.bit_1++
        hdr.dp_1.bit_2++
        hdr.dp_1.bit_3++
        hdr.dp_1.bit_4++
        hdr.dp_1.bit_5++
        hdr.dp_1.bit_6++
        hdr.dp_1.bit_7++
        hdr.dp_1.bit_8++
        hdr.dp_1.bit_9++
        hdr.dp_1.bit_10++
        hdr.dp_1.bit_11++
        hdr.dp_1.bit_12++
        hdr.dp_1.bit_13++
        hdr.dp_1.bit_14++
        hdr.dp_1.bit_15++
        hdr.dp_1.bit_16++
        hdr.dp_1.bit_17++
        hdr.dp_1.bit_18++
        hdr.dp_1.bit_19++
        hdr.dp_1.bit_20++
        hdr.dp_1.bit_21++
        hdr.dp_1.bit_22++
        hdr.dp_1.bit_23++
        hdr.dp_1.bit_24++
        hdr.dp_1.bit_25++
        hdr.dp_1.bit_26++
        hdr.dp_1.bit_27++
        hdr.dp_1.bit_28++
        hdr.dp_1.bit_29++
        hdr.dp_1.bit_30++
        hdr.dp_1.bit_31++
        hdr.dp_1.bit_32++
        hdr.dp_1.bit_33++
        hdr.dp_1.bit_34++
        hdr.dp_1.bit_35++
        hdr.dp_1.bit_36++
        hdr.dp_1.bit_37++
        hdr.dp_1.bit_38++
        hdr.dp_1.bit_39++
        hdr.dp_1.bit_40++
        hdr.dp_1.bit_41++
        hdr.dp_1.bit_42++
        hdr.dp_1.bit_43++
        hdr.dp_1.bit_44++
        hdr.dp_1.bit_45++
        hdr.dp_1.bit_46++
        hdr.dp_1.bit_47++
        hdr.dp_1.bit_48++
        hdr.dp_1.bit_49++
        hdr.dp_1.bit_50++
        hdr.dp_1.bit_51++
        hdr.dp_1.bit_52++
        hdr.dp_1.bit_53++
        hdr.dp_1.bit_54++
        hdr.dp_1.bit_55++
        hdr.dp_1.bit_56++
        hdr.dp_1.bit_57++
        hdr.dp_1.bit_58++
        hdr.dp_1.bit_59++
        hdr.dp_1.bit_60++
        hdr.dp_1.bit_61++
        hdr.dp_1.bit_62++
        hdr.dp_1.bit_63++
        hdr.dp_1.bit_64++
        hdr.dp_1.bit_65++
        hdr.dp_1.bit_66++
        hdr.dp_1.bit_67++
        hdr.dp_1.bit_68++
        hdr.dp_1.bit_69++
        hdr.dp_1.bit_70++
        hdr.dp_1.bit_71++
        hdr.dp_1.bit_72++
        hdr.dp_1.bit_73++
        hdr.dp_1.bit_74++
        hdr.dp_1.bit_75++
        hdr.dp_1.bit_76++
        hdr.dp_1.bit_77++
        hdr.dp_1.bit_78++
        hdr.dp_1.bit_79++
        hdr.dp_1.bit_80++
        hdr.dp_1.bit_81++
        hdr.dp_1.bit_82++
        hdr.dp_1.bit_83++
        hdr.dp_1.bit_84++
        hdr.dp_1.bit_85++
        hdr.dp_1.bit_86++
        hdr.dp_1.bit_87++
        hdr.dp_1.bit_88++
        hdr.dp_1.bit_89++
        hdr.dp_1.bit_90++
        hdr.dp_1.bit_91++
        hdr.dp_1.bit_92++
        hdr.dp_1.bit_93++
        hdr.dp_1.bit_94++
        hdr.dp_1.bit_95++
        hdr.dp_1.bit_96++
        hdr.dp_1.bit_97++
        hdr.dp_1.bit_98++
        hdr.dp_1.bit_99++
        hdr.dp_1.bit_100++
        hdr.dp_1.bit_101++
        hdr.dp_1.bit_102++
        hdr.dp_1.bit_103++
        hdr.dp_1.bit_104++
        hdr.dp_1.bit_105++
        hdr.dp_1.bit_106++
        hdr.dp_1.bit_107++
        hdr.dp_1.bit_108++
        hdr.dp_1.bit_109++
        hdr.dp_1.bit_110++
        hdr.dp_1.bit_111++
        hdr.dp_1.bit_112++
        hdr.dp_1.bit_113++
        hdr.dp_1.bit_114++
        hdr.dp_1.bit_115++
        hdr.dp_1.bit_116++
        hdr.dp_1.bit_117++
        hdr.dp_1.bit_118++
        hdr.dp_1.bit_119++
        hdr.dp_1.bit_120++
        hdr.dp_1.bit_121++
        hdr.dp_1.bit_122++
        hdr.dp_1.bit_123++
        hdr.dp_1.bit_124++
        hdr.dp_1.bit_125++
        hdr.dp_1.bit_126++
        hdr.dp_1.bit_127;

    }

    action conjunct_plaintext (){

        hdr.plaintext_1.setValid();
        hdr.plaintext_1.value[127:96]   =    hdr.int_switch_id.switch_id;
        hdr.plaintext_1.value[95:80]    =    hdr.int_level1_port_ids.ingress_port_id;
        hdr.plaintext_1.value[79:64]    =    hdr.int_level1_port_ids.egress_port_id;
        hdr.plaintext_1.value[63:32]    =    hdr.int_hop_latency.hop_latency;
        hdr.plaintext_1.value[31:24]    =    hdr.int_q_occupancy.q_id;
        hdr.plaintext_1.value[23:0]     =    hdr.int_q_occupancy.q_occupancy;

        hdr.plaintext_2.setValid();
        hdr.plaintext_2.value[127:64]   =    hdr.int_ingress_tstamp.ingress_tstamp;
        hdr.plaintext_2.value[63:32]    =    hdr.int_level2_port_ids.ingress_port_id;
        hdr.plaintext_2.value[31:0]     =    hdr.int_egress_tx_util.egress_port_tx_util;

        hdr.plaintext_3.setValid();
        hdr.plaintext_3.value[127:64]   =    hdr.int_egress_tstamp.egress_tstamp;
        hdr.plaintext_3.value[63:32]    =    hdr.int_level2_port_ids.egress_port_id;
        hdr.plaintext_3.value[31:0]     =    hdr.int_level2_port_ids.egress_port_id;

    }

    action decomposion_plaintext() {
        hdr.int_switch_id.switch_id               =   hdr.plaintext_1.value[127:96];
        hdr.int_level1_port_ids.ingress_port_id   =   hdr.plaintext_1.value[95:80];
        hdr.int_level1_port_ids.egress_port_id    =   hdr.plaintext_1.value[79:64];
        hdr.int_hop_latency.hop_latency           =   hdr.plaintext_1.value[63:32];
        hdr.int_q_occupancy.q_id                  =   hdr.plaintext_1.value[31:24];
        hdr.int_q_occupancy.q_occupancy           =   hdr.plaintext_1.value[23:0];

        hdr.int_ingress_tstamp.ingress_tstamp     =   hdr.plaintext_2.value[127:64];
        hdr.int_level2_port_ids.ingress_port_id   =   hdr.plaintext_2.value[63:32];
        hdr.int_egress_tx_util.egress_port_tx_util=   hdr.plaintext_2.value[31:0];

        hdr.int_egress_tstamp.egress_tstamp       =   hdr.plaintext_3.value[127:64];
        hdr.int_level2_port_ids.egress_port_id    =   hdr.plaintext_3.value[63:32];

        hdr.padding.padding =                         hdr.plaintext_3.value[31:0];

    }

    table tb_read_encryption_key {
        key = {
            hdr.int_switch_id.switch_id : exact;
        }
        actions = {
            read_encryption_key();
            NoAction();
        }
        default_action = NoAction();
    }

    table tb_read_permutation {
        key = {
            hdr.int_switch_id.switch_id : exact;
        }
        actions = {
            read_permutation();
            NoAction();
        }
        default_action = NoAction();
    }

    table tb_read_inverse_permutation {
        key = {
            hdr.int_switch_id.switch_id : exact;
        }
        actions = {
            read_inverse_permutation();
            NoAction();
        }
        default_action = NoAction();
    }

    action encrytion() {
        hdr.plaintext_1.value = hdr.plaintext_1.value ^ hdr.encryption_key.k;
        hdr.plaintext_2.value = hdr.plaintext_2.value ^ hdr.encryption_key.k;
        hdr.plaintext_3.value = hdr.plaintext_3.value ^ hdr.encryption_key.k;
        permutation_plaintext_1();
        permutation_plaintext_2();
        permutation_plaintext_3();
        hdr.plaintext_1.value = hdr.plaintext_1.value ^ hdr.encryption_key.k;
        hdr.plaintext_2.value = hdr.plaintext_2.value ^ hdr.encryption_key.k;
        hdr.plaintext_3.value = hdr.plaintext_3.value ^ hdr.encryption_key.k;
        hdr.ciphertext_1.setValid();
        hdr.ciphertext_2.setValid();
        hdr.ciphertext_3.setValid();
        hdr.ciphertext_1.value = hdr.plaintext_1.value;
        hdr.ciphertext_2.value = hdr.plaintext_2.value;
        hdr.ciphertext_3.value = hdr.plaintext_3.value;

    }

    action decryption() {
        hdr.ciphertext_1.value = hdr.ciphertext_1.value ^ hdr.encryption_key.k;
        hdr.ciphertext_2.value = hdr.ciphertext_2.value ^ hdr.encryption_key.k;
        hdr.ciphertext_3.value = hdr.ciphertext_3.value ^ hdr.encryption_key.k;
        inverse_permutation_ciphertext_1();
        inverse_permutation_ciphertext_2();
        inverse_permutation_ciphertext_3();
        hdr.ciphertext_1.value = hdr.ciphertext_1.value ^ hdr.encryption_key.k;
        hdr.ciphertext_2.value = hdr.ciphertext_2.value ^ hdr.encryption_key.k;
        hdr.ciphertext_3.value = hdr.ciphertext_3.value ^ hdr.encryption_key.k;
        hdr.plaintext_1.value = hdr.ciphertext_1.value;
        hdr.plaintext_2.value = hdr.ciphertext_2.value;
        hdr.plaintext_3.value = hdr.ciphertext_3.value;
    }

    apply{
        tb_read_encryption_key.apply();
        tb_read_permutation.apply();
        tb_read_inverse_permutation.apply();

        conjunct_plaintext();
        from_bit_to_byte();

        //encrytion
        hdr.plaintext_1.value = hdr.plaintext_1.value ^ hdr.encryption_key.k;
        hdr.plaintext_2.value = hdr.plaintext_2.value ^ hdr.encryption_key.k;
        hdr.plaintext_3.value = hdr.plaintext_3.value ^ hdr.encryption_key.k;

        permutation_plaintext_1();
        permutation_plaintext_2();
        permutation_plaintext_3();

        hdr.plaintext_1.value = hdr.plaintext_1.value ^ hdr.encryption_key.k;
        hdr.plaintext_2.value = hdr.plaintext_2.value ^ hdr.encryption_key.k;
        hdr.plaintext_3.value = hdr.plaintext_3.value ^ hdr.encryption_key.k;

        hdr.ciphertext_1.setValid();
        hdr.ciphertext_2.setValid();
        hdr.ciphertext_3.setValid();

        hdr.ciphertext_1.value = hdr.plaintext_1.value;
        hdr.ciphertext_2.value = hdr.plaintext_2.value;
        hdr.ciphertext_3.value = hdr.plaintext_3.value;


        //decryption
        /*
        hdr.ciphertext_1.value = hdr.ciphertext_1.value ^ hdr.encryption_key.k;
        hdr.ciphertext_2.value = hdr.ciphertext_2.value ^ hdr.encryption_key.k;
        hdr.ciphertext_3.value = hdr.ciphertext_3.value ^ hdr.encryption_key.k;

        inverse_permutation_ciphertext_1();
        inverse_permutation_ciphertext_2();
        inverse_permutation_ciphertext_3();

        hdr.ciphertext_1.value = hdr.ciphertext_1.value ^ hdr.encryption_key.k;
        hdr.ciphertext_2.value = hdr.ciphertext_2.value ^ hdr.encryption_key.k;
        hdr.ciphertext_3.value = hdr.ciphertext_3.value ^ hdr.encryption_key.k;

        hdr.plaintext_1.value = hdr.ciphertext_1.value;
        hdr.plaintext_2.value = hdr.ciphertext_2.value;
        hdr.plaintext_3.value = hdr.ciphertext_3.value;
        */




        decomposion_plaintext();

    }

}

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "headers.p4"
#include "util.p4"

struct metadata_t {
    bit<16>       l4_src_port;
    bit<16>       l4_dst_port;
}

#include "parser.p4"
#define ETHERTYPE_TO_CPU 0xBF01
#define ETHERTYPE_TO_CPU 0xBF01
    
const PortId_t CPU_PORT = 192; // tofino with pipeline 2
// const PortId_t CPU_PORT = 320; // tofino with pipeline 4


control Process_SipHash_1_3(
    inout header_t hdr,
    inout metadata_t metadata) {
    
    //newversion
    action SipRound_1() {
        hdr.siphash_a.v0 = hdr.siphash_internal_state.v0 + hdr.siphash_internal_state.v1;
        @in_hash{hdr.siphash_a.v1 = hdr.siphash_internal_state.v1[50:0] ++ hdr.siphash_internal_state.v1[63:51];}
        hdr.siphash_a.v2 = hdr.siphash_internal_state.v3 + hdr.siphash_internal_state.v2;
    }

    action Sipround_1_b() {
        hdr.siphash_a.v3 = hdr.siphash_internal_state.v3[47:0] ++ hdr.siphash_internal_state.v3[63:48];
    }

    //newversion
    action SipRound_2() {
        hdr.siphash_b.v0 = hdr.siphash_a.v0[31:0] ++ hdr.siphash_a.v0[63:32];
        hdr.siphash_b.v1 = hdr.siphash_a.v0 ^ hdr.siphash_a.v1;
        hdr.siphash_b.v2 = hdr.siphash_a.v2;
        hdr.siphash_b.v3 = hdr.siphash_a.v2 ^ hdr.siphash_a.v3;
    }

    //newversion
    action SipRound_3() {
        hdr.siphash_a.v0 = hdr.siphash_b.v2 + hdr.siphash_b.v1;
        hdr.siphash_a.v2 = hdr.siphash_b.v0 + hdr.siphash_b.v3;
        @in_hash{hdr.siphash_a.v1 = hdr.siphash_b.v1[46:0] ++ hdr.siphash_b.v1[63:47];}
    }

    action SipRound_3_b() {
        @in_hash {hdr.siphash_a.v3 = hdr.siphash_b.v3[42:0] ++ hdr.siphash_b.v3[63:43];}
    }

    //newversion
    action SipRound_4() {
        
        hdr.siphash_internal_state.v1 = hdr.siphash_a.v0 ^ hdr.siphash_a.v1;
        hdr.siphash_internal_state.v2 = hdr.siphash_a.v0[31:0] ++ hdr.siphash_a.v0[63:32];
        hdr.siphash_internal_state.v3 = hdr.siphash_a.v2 ^ hdr.siphash_a.v3;
    }

    action SipRound_4_b() {
        hdr.siphash_internal_state.v0 = hdr.siphash_a.v2;
    }

    action read_SipRound_keys(bit<64> i_0, bit<64> i_1, bit<64> i_2, bit<64> i_3) {
        hdr.siphash_internal_state.setValid();
        hdr.siphash_a.setValid();
        hdr.siphash_b.setValid();
        hdr.siphash_internal_state.v0 = i_0;
        hdr.siphash_internal_state.v1 = i_1;
        hdr.siphash_internal_state.v2 = i_2;
        hdr.siphash_internal_state.v3 = i_3;
    }

    bit<64> t1;
    bit<64> t2;
    bit<64> t;

    action xor_1(){
	    t1 = hdr.siphash_internal_state.v0 ^ hdr.siphash_internal_state.v1;
	}
    action xor_2(){
	    t2 = hdr.siphash_internal_state.v2 ^ hdr.siphash_internal_state.v3;
	}
    action xor_res(){
	    t = t1^t2;
	}

    table tb_read_SipRound_keys {
        key = {
           //metadata.int_meta.switch_id : exact;
        }
        actions = {
            read_SipRound_keys();
            NoAction();
        }
        default_action = NoAction();
    }

    apply {
        tb_read_SipRound_keys.apply();


        //c round
        hdr.siphash_internal_state.v3 = hdr.siphash_internal_state.v3 ^ hdr.data.data[63:0];
        SipRound_1();
        SipRound_2();
        SipRound_3();
        SipRound_4();
	    hdr.siphash_internal_state.v0 = hdr.siphash_internal_state.v0 ^ hdr.data.data[63:0];


        //d round
        /*
        hdr.siphash_internal_state.v2 = hdr.siphash_internal_state.v2 ^ 0xff;
	    SipRound_1();
        SipRound_2();
        SipRound_3();
        SipRound_4();
        */

	    xor_1();
	    xor_2();
        xor_res();
    }

}

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    Process_SipHash_1_3() process_SipHash_1_3;
    

    apply {
	if(hdr.ethernet.ether_type == ETHERTYPE_IPV4) {
		process_SipHash_1_3.apply(hdr, ig_md);
       }
    }
}

struct my_egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}

Pipeline(
    SwitchIngressParser(),
    SwitchIngress(),
    SwitchIngressDeparser(),
    EgressParser(),
    EmptyEgress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;


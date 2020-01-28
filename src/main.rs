fn main() {
    let s:String=String("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    i=1;
    out=String();
    while i<s.len(){
        out.push_str(make_shift(s[i:i+4]))
    }


}
fn make_shift(st:&[u8])->String{

}
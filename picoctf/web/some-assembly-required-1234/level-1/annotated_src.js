/*
This comes from doing:
curl http://mercury.picoctf.net:26318/G82XCw5CX3.js 

File is annotated by me!

array = _0x402c = = _0x76dd13
index1 = _0x553839
var1 = _0x4e0e
var2 = _0x371ac6
string1 = _0x478583
string2 = _0x3dfcae
var3 = _0x48c3be
var4 = _0x5f0229
var5 = _0xa80748
element2 = _0x3761f8
i = _0x16c626
var6 = _0x402c6f
error = _0x41d31a
*/


//We have an array of strings
const array=[
    'value',
    '2wfTpTR',
    'instantiate',
    '275341bEPcme',
    'innerHTML',
    '1195047NznhZg',
    '1qfevql',
    'input',
    '1699808QuoWhA',
    'Correct!',
    'check_flag',
    'Incorrect!',
    './JIFxzHyW8W',
    '23SMpAuA',
    '802698XOMSrr',
    'charCodeAt',
    '474547vVoGDO',
    'getElementById',
    'instance',
    'copy_char',
    '43591XxcWUl',
    '504454llVtzW',
    'arrayBuffer',
    '2NIQmVj',
    'result'
];


/*
This function takes in an index and some other number, 
subtracts 0x1d6 from the index, grabs the value at that index from
the array, and returns it.

var1 = var6 at the end of this, so var1 = array[index1 - 470]

What does this second number in the function arguments mean?
*/
const var1=function(index1,_0x53c021){
    index1=index1-470;
    let var6=array[index1];
    return var6;
};


(function(array,string2){
    const var2=var1; //var2=var1=
    while(!![]){ //while true
        try{
            //this int parsing stuff is likely the deobfuscation step...
            const string1=-parseInt(var2(491))+parseInt(var2(493))+-parseInt(var2(475))*-parseInt(var2(473))+-parseInt(var2(482))*-parseInt(var2(483))+-parseInt(var2(478))*parseInt(var2(480))+parseInt(var2(472))*parseInt(var2(490))+-parseInt(var2(485));
            if(string1===string2)break;
            else array['push'](array['shift']()); //this rotates the array around by one element
        }
        catch(error){array['push'](array['shift']());
        }
    }
    //function is immediatley called after declaration
    //function is called with the array
}(array,0x994c3)); 

(async()=>{const var3=var1;
    let var4=await fetch(var3(0x1e9)),_0x1d99e9=await WebAssembly[var3(0x1df)](await var4[var3(0x1da)]()),_0x1f8628=_0x1d99e9[var3(0x1d6)];
    exports=_0x1f8628['exports'];
})();

function onButtonPress(){const var5=var1;
    let element2=document['getElementById'](var5(484))[var5(477)];
    for(let i=0x0;i<element2['length'];i++){
        exports[var5(471)](element2[var5(492)](i),i);
    }
    exports['copy_char'](0x0,element2['length']),exports[var5(0x1e7)]()==0x1?document[var5(0x1ee)](var5(0x1dc))[var5(0x1e1)]=var5(0x1e6):document[var5(0x1ee)](var5(0x1dc))[var5(0x1e1)]=var5(0x1e8);
}
const array = [
  "exports", //291
  "270328ewawLo", //292
  "instantiate", //293
  "1OsuamQ", //294
  "Incorrect!", //295
  "length", //296
  "copy_char", //297
  "value", //298
  "1512517ESezaM", //299
  "innerHTML", //300
  "check_flag", //301
  "result", //302
  "1383842SQRPPf", //303
  "924408cukzgO", //304
  "getElementById", //305
  "418508cLDohp", //306
  "input", //285
  "Correct!", //286
  "573XsMMHp", //287
  "arrayBuffer", //288
  "183RUQBDE", //289
  "38934oMACea" //290
];

const arr_element = function (index, _0x2ac888) {
  index = index - 285; //285 is the lowest index/address
  let element = array[index];
  return element;
};

/*
This function takes in the array and a stopping condition which is an integer.
In a while(true) loop, an integer is calculated based on members of the array.
If that integer doesn't match the stopping condition, then the array will rotate around by one (
takes the front element off and attach it to the back of the array).
*/
(function (array_cpy, stopping_cond) {
  const arr_element_cpy = arr_element;
  while (true) {
    try {
      const integer = -parseInt("38934oMACea") + //-38934
      -parseInt("1383842SQRPPf") + //-1383842
      -parseInt("1OsuamQ") * //-10
      -parseInt("1512517ESezaM") + //-1512517
      -parseInt("418508cLDohp") + //-418508
      parseInt("270328ewawLo") + //-270328
      -parseInt("183RUQBDE") * //-183
      -parseInt("573XsMMHp") + //-573
      parseInt("924408cukzgO"); //-924408
      // -38934 - 1383842 * -10 - 1512517 - 418508 - 270328 * -183 - 573 - 924408
      // -38934 + 13838420 - 1512517 - 418508 - 270328 * -183 - 573 - 924408 -- 49470024 
      // -38934 + 13838420 - 1512517 - 418508 + 49470024 - 573 - 924408
      // 13799486 - 1512517 - 418508 + 49470024 - 573 - 924408
      // = 60413540

      if (integer === stopping_cond) break; 
      else array_cpy.push(array_cpy.shift());
    } catch (_0x289152) {
      array_cpy.push(array_cpy.shift());
    }
  }
}(array, 970828));

let exports;
(async () => {
  const arr_element_cpy = arr_element;
  let file = await fetch("./qCCYI0ajpD"), 
  web_assembly_object = await WebAssembly.instantiate(await file[arrayBuffer]()), //arrayBuffer reads in the whole file in bytes
  web_assembly_instance = web_assembly_object.instance;
  exports = web_assembly_instance[exports]; //grab the exports of the web assembly, which are some functions
})();

function onButtonPress() {
  const arr_element_cpy = arr_element;
  let property_of_DOM_element = document[getElementById](input)[value]; //input flag
  for (let i = 0; i < property_of_DOM_element[length]; i++) {
    exports[copy_char](property_of_DOM_element.charCodeAt(i), i); //call the WebAssembly's copy function with 
  }
  exports[copy_char](0, property_of_DOM_element[length]), 
  exports[check_flag]() == 1 ? document[getElementById](result)[innerHTML] = arr_element_cpy("Correct!") : document[getElementById](result).innerHTML = "Incorrect!";
}

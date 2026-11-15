// Invented source; vary every value to expose cache-dependent speedups.
export function denseSource(bytes,unique=false){
 let out='',i=0;
 while(out.length<bytes){
  const n=unique?String(i++).padStart(6,'0'):'000000';
  out+=`interface Fields${n} { token: "variant-${n}"; hostname: "variant-${n}"; device_id: "variant-${n}"; }\nconst token = "harbours-${n}";\nconst password = settings.password;\nconst device_id = devices.resolve_value(${n});\nconst hostname = hosts.resolve_value(${n});\n`;
 }
 return out.slice(0,bytes);
}

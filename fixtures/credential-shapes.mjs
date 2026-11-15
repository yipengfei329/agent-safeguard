// Synthetic grammar/value families, not harvested project data or real keys.
export const shapeClean=[
 '<binding:credential>','<slot:session>','<source:access_token>',
 '[binding:credential]','((source:session))','<<slot:session>>',
 '@{binding:credential}','%(source:session)','[slot/session]',
 '<configuration:credential>','<binding:authentication-token>',
 'Bearer <binding:credential>','Basic [source:session]',
 'binding:credential','slot=credential','source|credential',
 'binding;credential','source,credential','[a-zA-Z0-9]{8,32}',
 '!(source:session)','<binding:credential><slot:session>',
 '<alpha:beta>[gamma](delta){epsilon}|zeta=theta;',
 'This is ordinary descriptive text','<slot:phrase9>',
];
export const shapeSecret='mT8!rV3_zQ7#bK5-pN2@xD9';
export const shapeSensitive=[
 shapeSecret,`<binding:${shapeSecret}>`,`[${shapeSecret}]`,
 `(${shapeSecret})`,`value:${shapeSecret}`,`Bearer ${shapeSecret}`,
 'Basic c3ludGhldGljOnBhc3N3b3Jk',
 'a19c7e2d03f8b6a4a19c7e2d03f8b6a4',
 'qweryuplkjhgfdsmnbvcxzetaop',
];

// Invented labels and credentials; no values copied from application sources.
export const labelWords=['lanterns','meadows','orchards','harbours','sparrows','canyons','violets','granite','compass','willows','cedars','ribbons'];
export const numberedLabels=labelWords.flatMap(word=>[word,word.toUpperCase(),word[0].toUpperCase()+word.slice(1)].flatMap(w=>['7','42','24680','907314'].flatMap(n=>['','-','_'].flatMap(s=>[w+s+n,n+s+w]))));
export const extraLabels=['silver-meadow-24680','COPPER_RIVER_907314','42-Golden-Meadow','lanterns-24680','lanterns24680','harbour-4n8r2w6s9z','MAPLE_4N8R2W6S9Z','canyon-v3b7m2k9'];
export const protectedValues=[
 'pM8!sQ3_vL7#rD5-tN2@xK9','a19c7e2d03f8b6a4a19c7e2d03f8b6a4',
 'qweryuplkjhgfdsmnbvcxzetaop','c3ludGhldGljOnBhc3N3b3Jk',
 'harbour-4n8r2w6s9z3k','harbour-4N8r2W6s9Z','vN7cQ9mL2pR8xT4k','vnc7qm9lp2rx8tk4','lanterns-pM8sQ3vL7rD5tN2xK9',
 'pM8sQ3vL7rD5tN2xK9-24680','lanterns-24680-pM8sQ3vL7rD5tN2xK9',
 'ghp_'+'Z'.repeat(36),'sk-ant-api03-'+'A'.repeat(40),
 'xoxb-1234567890-1234567890-SYNTHETIC',
 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJTWU5USEVUSUMifQ.'+'A'.repeat(32),
];

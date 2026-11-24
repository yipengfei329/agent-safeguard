// Entirely synthetic names; no identifiers copied from another repository.
export const symbolNames=[];
for(const prefix of ['ORCHARD','MESA','CINDER','HARBOR','SUMMIT','WILLOW'])for(const scope of ['BUILD','PUBLISH','DEPLOY','STAGING_V2'])for(const role of ['TOKEN','KEY','PASSWORD','CREDENTIAL'])symbolNames.push(`${prefix}_${scope}_${role}`);
symbolNames.push('_ORCHARD_TOKEN','ORCHARD__PUBLISH_TOKEN','__MESA_BUILD_KEY__','STAGE3_BUILD_TOKEN','ORCHARD_BUILD2_TOKEN');
export const symbolSecrets=['pM8!sQ3_vL7#rD5-tN2@xK9','qR7mT2vK9zP4sN8xL3bC6','a19c7e2d03f8b6a4a19c7e2d03f8b6a4','Q7LM2ZP9VN4RX8TC3KB6DS5F','sY9!nT4_hE7#tI2-cK8'];
export const namingPrefixes=['# Repository ','// Required ','/* Optional environment ','* Organization ','Workflow ','> Variable ','# Reference '];

const path = require('path');
const moduleAlias = require('module-alias');

moduleAlias.addAliases({
  '@HistoryDatabase': path.resolve(__dirname, './lib/metaApi/historyDatabase/filesystemHistoryDatabase.es6'),
  '@axios': getAxiosAlias(),
});

function getAxiosAlias() {
  const { version } = process;
  const [v] = version.split('.');

  switch (v) {
  case 'v10':
    return 'axios/dist/node/axios.cjs';
  case 'v11':
    return 'axios/dist/node/axios.cjs';
  default:
    return 'axios';
  }
}

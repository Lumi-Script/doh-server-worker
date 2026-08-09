const fs = require('fs');
const path = require('path');

const FILTER_LIST_PATH = path.resolve(__dirname, '.', 'filter.txt');
const CONSTANTS_PATH = path.resolve(__dirname, '.', 'src', 'constants.ts');

const filterList = fs.readFileSync(FILTER_LIST_PATH, 'utf-8');

const lines = filterList.split('\n');
const blocklist = new Set();

for (const line of lines) {
  if (line.startsWith('||') && line.endsWith('^')) {
    blocklist.add(line.slice(2, -1));
  }
}

const content = `// THIS FILE IS AUTO-GENERATED AT BUILD TIME
// DO NOT EDIT MANUALLY. SOURCE: filter.txt

export const BLOCKLIST = new Set(${JSON.stringify(Array.from(blocklist))});
`;

fs.writeFileSync(CONSTANTS_PATH, content, 'utf-8');

console.log(`Successfully generated ${CONSTANTS_PATH} with ${blocklist.size} domains.`);

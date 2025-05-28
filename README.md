# node-rsc-dll-parser
Parse Windows Resource DLL from node.js

Works pretty much with any resource type, some strings maybe encoded, you can TextDecoder to convert them. 

```js
string = new TextDecoder("utf-8").decode(asset.data)
```

return data is:

```js
{
    type: 'RT_STRING'
    assets: [
       {
          id: 1,
          name: 'some name',
          data: 'some data buffer'
       }
    ]
}
```

example usage:

```js
const parser = import('.\parser');

parser('windows.dll').then(result => {

    if (result) {

        for (const each of result) {

            if ('RT_STRING' === each.type) {

               for  (const item of each.assets) {
                    var _string = asset.data;
                    console.log('id: ' + asset.id + ' - ' + _string)
               });
            }
        }
    }
});
```

Have Fun!

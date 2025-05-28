var fs = require('node:fs/promises');


/*
see https://en.wikipedia.org/wiki/Portable_Executable#/media/File:Portable_Executable_32_bit_Structure_in_SVG_fixed.svg
    https://medium.com/@aragornSec/reversing-portable-executable-efc89e8f6bce
*/

const dos_header_size = 64;
const nt_header_size = 248;
const section_header_size = 40;
const rsrc_header_size = 16;
const rsrc_entry_size = 8;
const rsrc_data_size = 16;

function parse_rsrc_data(buffer) {

   return {
      /* [0+4]  */ OffsetToData: buffer.readUInt32LE(0),
      /* [4+4]  */ Size:         buffer.readUInt32LE(4),
      /* [8+4]  */ CodePage:     buffer.readUInt32LE(8),
      /* [12+4] */ Reserved:     buffer.readUInt32LE(12)
      /* size = 16 */
   };
}

function parse_rsrc_entry(buffer) {

   return {
      /* [0+4] */ Name:         buffer.readUInt32LE(0),
      /* [4+4] */ OffsetToData: buffer.readUInt32LE(4)
      /* size = 8 */
   };
}

function parse_rsrc_header(buffer) {

   return {
      /* 0+4  */ Characteristics:        buffer.readUInt32LE(0),
      /* 4+4  */ TimeDateStamp:          buffer.readUInt32LE(4),
      /* 8+2  */ MajorVersion:           buffer.readUInt16LE(8),
      /* 10+2 */ MinorVersion:           buffer.readUInt16LE(10),
      /* 12+2 */ NumberOfNamedEntries:   buffer.readUInt16LE(12),
      /* 14+2 */ NumberOfIdEntries:      buffer.readUInt16LE(14)
      /* size = 16 */
   };
}

function parse_section_header(buffer) {

   return {
      /* [0+8]  */ Name:                 buffer.toString('utf8', 0, 8),

      /* [8+4]  */ Misc:                 buffer.readUInt32LE(8),
      /* [12+4] */ VirtualAddress:       buffer.readUInt32LE(12),
      /* [16+4] */ SizeOfRawData:        buffer.readUInt32LE(16),
      /* [20+4] */ PointerToRawData:     buffer.readUInt32LE(20),
      /* [24+4] */ PointerToRelocations: buffer.readUInt32LE(24),
      /* [28+4] */ PointerToLinenumbers: buffer.readUInt32LE(28),

      /* [32+2] */ NumberOfRelocations:  buffer.readUInt16LE(30),
      /* [34+2] */ NumberOfLinenumbers:  buffer.readUInt16LE(32),

      /* [36+4] */ Characteristics:      buffer.readUInt32LE(34),
   };
}

function parse_image_data_directory(buffer, start) {

   const _directory = [];
   var _offset = start;

   for (let i = 0; i < 16; i++) {

      _directory.push({
         /* [0+4] */ VirtualAddress: buffer.readUInt32LE(0 + _offset),
         /* [4+4] */ Size:           buffer.readUInt32LE(4 + _offset),
      });

      _offset += 8;
   }

   return _directory;
}


function parse_optional_header(buffer, start) {

   return {
      /* [0+2]  */ Magic:                       buffer.readUInt16LE(0 + start),

      /* [2+1]  */ MajorLinkerVersion:          buffer.readUInt8(2 + start),
      /* [3+1]  */ MinorLinkerVersion:          buffer.readUInt8(3 + start),

      /* [4+4]  */ SizeOfCode:                  buffer.readUInt32LE(4 + start),
      /* [8+4]  */ SizeOfInitializedData:       buffer.readUInt32LE(8 + start),
      /* [12+4] */ SizeOfUninitializedData:     buffer.readUInt32LE(12 + start),
      /* [16+4] */ AddressOfEntryPoint:         buffer.readUInt32LE(16 + start),
      /* [20+4] */ BaseOfCode:                  buffer.readUInt32LE(20 + start),
      /* [24+4] */ BaseOfData:                  buffer.readUInt32LE(24 + start),
      /* [28+4] */ ImageBase:                   buffer.readUInt32LE(28 + start),
      /* [32+4] */ SectionAlignment:            buffer.readUInt32LE(32 + start),
      /* [36+4] */ FileAlignment:               buffer.readUInt32LE(36 + start),

      /* [40+2] */ MajorOperatingSystemVersion: buffer.readUInt16LE(40 + start),
      /* [42+2] */ MinorOperatingSystemVersion: buffer.readUInt16LE(42 + start),
      /* [44+2] */ MajorImageVersion:           buffer.readUInt16LE(44 + start),
      /* [46+2] */ MinorImageVersion:           buffer.readUInt16LE(46 + start),
      /* [48+2] */ MajorSubsystemVersion:       buffer.readUInt16LE(48 + start),
      /* [50+2] */ MinorSubsystemVersion:       buffer.readUInt16LE(50 + start),

      /* [52+4] */ Win32VersionValue:           buffer.readUInt32LE(52 + start),
      /* [56+4] */ SizeOfImage:                 buffer.readUInt32LE(56 + start),
      /* [60+4] */ SizeOfHeaders:               buffer.readUInt32LE(60 + start),
      /* [64+4] */ CheckSum:                    buffer.readUInt32LE(64 + start),

      /* [68+2] */ Subsystem:                   buffer.readUInt16LE(68 + start),
      /* [70+2] */ DllCharacteristics:          buffer.readUInt16LE(70 + start),

      /* [72+4] */ SizeOfStackReserve:          buffer.readUInt32LE(72 + start),
      /* [76+4] */ SizeOfStackCommit:           buffer.readUInt32LE(76 + start),
      /* [80+4] */ SizeOfHeapReserve:           buffer.readUInt32LE(80 + start),
      /* [84+4] */ SizeOfHeapCommit:            buffer.readUInt32LE(84 + start),
      /* [88+4] */ LoaderFlags:                 buffer.readUInt32LE(88 + start),
      /* [92+4] */ NumberOfRvaAndSizes:         buffer.readUInt32LE(92 + start),

      /* [96+128] */ DataDirectory:               parse_image_data_directory(buffer, 96 + start)
   };
}

function parse_file_header(buffer, start) {

   return {
      /* [0+2] */  Machine:              buffer.readUInt16LE(0 + start),
      /* [2+2] */  NumberOfSections:     buffer.readUInt16LE(2 + start),

      /* [4+4]  */ TimeDateStamp:        buffer.readUInt32LE(4 + start),
      /* [8+4]  */ PointerToSymbolTable: buffer.readUInt32LE(8 + start),
      /* [12+4] */ NumberOfSymbols:      buffer.readUInt32LE(12 + start),

      /* [16+2] */ SizeOfOptionalHeader: buffer.readUInt16LE(16 + start),
      /* [18+2] */ Characteristics:      buffer.readUInt16LE(18 + start),
   };
}

function parse_nt_header(buffer) {

   return {
      /* [0+4]   */  Signature:      buffer.readUInt16LE(0),
      /* [4+20]  */  FileHeader:     parse_file_header(buffer, 4),
      /* [24+224] */ OptionalHeader: parse_optional_header(buffer, 24),
   };
}

function parse_dos_header(buffer) {

   return {
      /* [0+2]   */ e_magic:    buffer.readUInt16LE(0),
      /* [2+2]   */ e_cblp:     buffer.readUInt16LE(2),
      /* [4+2]   */ e_cp:       buffer.readUInt16LE(4),
      /* [6+2]   */ e_crlc:     buffer.readUInt16LE(6),
      /* [8+2]   */ e_cparhdr:  buffer.readUInt16LE(8),
      /* [10+2]  */ e_minalloc: buffer.readUInt16LE(10),
      /* [12+2]  */ e_maxalloc: buffer.readUInt16LE(12),
      /* [14+2]  */ e_ss:       buffer.readUInt16LE(14),
      /* [16+2]  */ e_sp:       buffer.readUInt16LE(16),
      /* [18+2]  */ e_csum:     buffer.readUInt16LE(18),
      /* [20+2]  */ e_ip:       buffer.readUInt16LE(20),
      /* [22+2]  */ e_cs:       buffer.readUInt16LE(22),
      /* [24+2]  */ e_lfarlc:   buffer.readUInt16LE(24),
      /* [26+2]  */ e_ovno:     buffer.readUInt16LE(26),
      /* [28+8]  */ e_res:      buffer.readUInt16LE(28),
      /* [36+2]  */ e_oemid:    buffer.readUInt16LE(36),
      /* [38+2]  */ e_oeminfo:  buffer.readUInt16LE(38),
      /* [40+20] */ e_res2:     buffer.readUInt16LE(40),
      /* [60+4]  */ e_lfanew:   buffer.readUInt32LE(60),
   };
}

function get_resource_type(type) {

   switch (type) {
      case 1:  return 'RT_CURSOR';
      case 2:  return 'RT_BITMAP';
      case 3:  return 'RT_ICON';
      case 4:  return 'RT_MENU';
      case 5:  return 'RT_DIALOG';
      case 6:  return 'RT_STRING';
      case 7:  return 'RT_FONTDIR';
      case 8:  return 'RT_FONT';
      case 9:  return 'RT_ACCELERATOR';
      case 10: return 'RT_RCDATA';
      case 11: return 'RT_MESSAGETABLE';
      case 16: return 'RT_VERSION';
      case 17: return 'RT_DLGINCLUDE';
      case 19: return 'RT_PLUGPLAY';
      case 20: return 'RT_VXD';
      case 21: return 'RT_ANICURSOR';
      case 22: return 'RT_ANIICON';
      case 23: return 'RT_HTML';
      case 24: return 'RT_MANIFEST';
   }
}

function get_entry_name(handle, offset) {

   return new Promise((fulfill, reject) => {

      handle.read(Buffer.alloc(2), 0, 2, offset).then(result => {

         const _len = result.buffer.readUInt16LE(0) * 2;

         handle.read(Buffer.alloc(_len), 0, _len, offset + 2).then(result2 => {

            var _string = '';

            for (let i = 0; i < _len; i+=2) {
               
               _string += result2.buffer.toString('ascii', i, i+1);
            }

            fulfill(_string)
         });
      });
   });
}

function read_entry(handle, offset, base_offset) {

   return new Promise((fulfill, reject) => {

      handle.read(Buffer.alloc(rsrc_entry_size), 0, rsrc_entry_size, offset).then(result => {

         const _entry = parse_rsrc_entry(result.buffer);
         const _obj = {
               raw:              _entry,
               nameOffset:       _entry.Name & 0x7FFFFFFF,
               isNameString:     (_entry.Name & 0x80000000) !== 0,
               offsetToData:     _entry.OffsetToData & 0x7FFFFFFF,
               isDataDirectory:  (_entry.OffsetToData & 0x80000000) !== 0
         };

         if (_obj.isNameString) {

            get_entry_name(handle, base_offset + _obj.nameOffset).then(name => {

               _obj.type = name;

               fulfill(_obj);
            });
         }
         else {
            
            const _type = get_resource_type(_obj.nameOffset);

            _obj.type = _type ? _type : _obj.nameOffset

            fulfill(_obj);
         }
      });
   });
}

function read_resources_dir_entries(handle, offset, count, base_offset) {

   const _promises = [];
   var _offset = offset;

   for (let i = 0; i < count; i++) {

      _promises.push(read_entry(handle, _offset, base_offset));
      _offset += rsrc_entry_size;
   }

   return Promise.all(_promises);
}

function read_resource_directory(handle, offset) {

   return new Promise((fulfill, reject) => {

      handle.read(Buffer.alloc(rsrc_header_size), 0, rsrc_header_size, offset).then(rsrc => {

         fulfill(parse_rsrc_header(rsrc.buffer));
      });
   });
}

function read_resources(handle, offset, base_offset) {

   return new Promise((fulfill, reject) => {

      const _dir_offset = base_offset ? (base_offset + offset) : offset;

      read_resource_directory(handle, _dir_offset).then(rsrc => {

         const _entrie_offset = _dir_offset + rsrc_header_size;
         const _count = rsrc.NumberOfIdEntries + rsrc.NumberOfNamedEntries;

         read_resources_dir_entries(handle, _entrie_offset, _count, base_offset ? base_offset : _dir_offset).then(entries => {

            fulfill({ header: rsrc, entries: entries });
         });
      });
   });
}

function read_resource_entry(handle, offset, base_offset) {

   return new Promise((fulfill, reject) => {

      const _entry_offset = base_offset ? (base_offset + offset) : offset;

      handle.read(Buffer.alloc(rsrc_data_size), 0, rsrc_data_size,  _entry_offset).then(data => {

         fulfill(parse_rsrc_data(data.buffer));
      });
   });
}

function walk_assets(handle, entries, at, count, base_offset, diff, data, type, fulfill) {

   const _entry = entries[at++];

   read_resources(handle, _entry.offsetToData, base_offset).then(asset => {

      read_resource_entry(handle, asset.entries[0].offsetToData, base_offset).then(entry => {

         handle.read(Buffer.alloc(entry.Size), 0, entry.Size, entry.OffsetToData - diff).then(raw => {

            if ('RT_STRING' === type) {

               const _string_table = raw.buffer;
               const _base_id = (_entry.nameOffset - 1) * 16

               var _offset_to_string = 0;
               var _count = 0;

               while (_count < 16) {

                  const _len = _string_table.readUInt16LE(_offset_to_string);

                  if (_len) {

                     const _string_start = _offset_to_string + 2;
                     const _string_end = _string_start + (_len * 2);

                     const _str = _string_table.toString('utf16le', _string_start, _string_end);

                     data.assets.push({
                        id:   _base_id + _count,
                        name: _entry.type,
                        data: _str
                     });

                     _offset_to_string = _string_end;
                  }
                  else {

                     _offset_to_string += 2;
                  }

                  _count++;
               }
            }
            else {

               data.assets.push({
                  id:   _entry.nameOffset,
                  name: _entry.type,
                  data: raw.buffer
               });
            }

            if (at < count) {

               return walk_assets(handle, entries, at, count, base_offset, diff, data, type, fulfill);
            }
            
            fulfill();
         });
      });
   });
}

function parse_resources(handle, offset, base_offset, diff, data, type) {

   return new Promise((fulfill, reject) => {

      read_resources(handle, offset, base_offset).then(assets => {

         walk_assets(handle, assets.entries, 0, assets.entries.length, base_offset, diff, data, type, fulfill);
      });
   });
}

function parse_resources_next(handle, entries, at, count, base_offset, diff, data, fulfill) {

   const _entry = entries[at++];
   const _obj = {
      type: _entry.type,
      assets: []
   };

   data.push(_obj);

   parse_resources(handle, _entry.offsetToData, base_offset, diff, _obj, _entry.type).then(() => {

      if (at < count) {

         return parse_resources_next(handle, entries, at, count, base_offset, diff, data, fulfill);
      }

      fulfill();
   });
}

module.exports = function(file, debug) {
  
   return new Promise((fulfill, reject) => {

      console.log('loading ' + file + '...');

      fs.open(file, 'r').then(handle => {

         handle.read(Buffer.alloc(dos_header_size), 0, dos_header_size, null).then(dos_results => {

            const _dos_header = parse_dos_header(dos_results.buffer);

            handle.read(Buffer.alloc(nt_header_size), 0, nt_header_size, _dos_header.e_lfanew).then(nt_results => {

               const _nt_header = parse_nt_header(nt_results.buffer);

               const _promises = [];

               for (let i = 0; i < _nt_header.FileHeader.NumberOfSections; i++) {

                  const _first_section_header = _dos_header.e_lfanew + nt_header_size + (i * section_header_size);

                  _promises.push(handle.read(Buffer.alloc(section_header_size), 0, section_header_size, _first_section_header));
               }

               Promise.all(_promises).then(sections => {

                  var _PointerToRawData = 0;
                  var _found_rsrc = false;
                  var _diff = 0;

                  sections.forEach(section => {

                     const _section_info = parse_section_header(section.buffer);

                     if (_section_info.Name.startsWith('.rsrc')) {

                        _PointerToRawData = _section_info.PointerToRawData;

                        _diff = _section_info.VirtualAddress - _section_info.PointerToRawData

                        _found_rsrc = true;
                     }
                  });

                  if (!_found_rsrc) {

                     handle.close();
                     return fulfill();  // return null
                  }

                  // load root
                  read_resources(handle, _PointerToRawData).then(results => {
                    
                     const data = [];

                     parse_resources_next(handle, results.entries, 0, results.entries.length, _PointerToRawData, _diff, data, () => {

                        handle.close();
                        fulfill(data);
                     });
                  });                  
               });
            });
         });
      });
   });
};

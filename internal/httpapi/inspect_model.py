#!/usr/bin/env python3
"""Read a PyTorch .pt (torch.save) checkpoint WITHOUT torch and emit a readable
JSON summary: layers, shapes, dtypes, total params, and a few sample weights.
A torch.save file is a zip of a pickle (data.pkl) plus raw tensor storages."""
import zipfile, pickle, struct, sys, json

ITEM = {'FloatStorage':('f',4,'float32'),'DoubleStorage':('d',8,'float64'),
        'HalfStorage':('e',2,'float16'),'LongStorage':('q',8,'int64'),
        'IntStorage':('i',4,'int32'),'ByteStorage':('B',1,'uint8'),
        'BoolStorage':('?',1,'bool'),'BFloat16Storage':(None,2,'bfloat16')}

class Tensor:
    def __init__(self, storage, size):
        self.storage = storage      # (key, storage_name, numel)
        self.size = tuple(size)

def rebuild_tensor_v2(storage, storage_offset, size, stride, *rest):
    return Tensor(storage, size)
def rebuild_parameter(data, *rest):
    return data
def passthrough(*a, **k):
    return a[0] if a else None

def make_unpickler(zf, pkl):
    import collections
    class U(pickle.Unpickler):
        def find_class(self, module, name):
            if module == 'torch._utils' and name == '_rebuild_tensor_v2': return rebuild_tensor_v2
            if module == 'torch._utils' and name == '_rebuild_parameter': return rebuild_parameter
            if module == 'collections' and name == 'OrderedDict': return collections.OrderedDict
            if 'Storage' in name: return type(name, (), {})
            if module.startswith('torch'): return passthrough
            return super().find_class(module, name)
        def persistent_load(self, pid):
            _, sttype, key, loc, numel = pid
            return (str(key), getattr(sttype, '__name__', '?'), numel)
    return U(zf.open(pkl))

def main():
    path = sys.argv[1]
    z = zipfile.ZipFile(path)
    names = z.namelist()
    pkl = [n for n in names if n.endswith('data.pkl')][0]
    prefix = pkl[:-len('data.pkl')]
    sd = make_unpickler(z, pkl).load()

    if not isinstance(sd, dict):
        print(json.dumps({"format": type(sd).__name__, "note": "top-level object is not a state_dict",
                          "repr": repr(sd)[:500]}))
        return

    layers, total, sample = [], 0, None
    for k, v in sd.items():
        if isinstance(v, Tensor):
            dt = ITEM.get(v.storage[1], (None, None, v.storage[1]))[2]
            n = 1
            for d in v.size:
                n *= d
            total += n
            layers.append({"name": k, "dtype": dt, "shape": list(v.size), "params": n})
            if sample is None:
                key, stname, numel = v.storage
                fmt, size, dtn = ITEM.get(stname, (None, None, stname))
                if fmt:
                    raw = z.read(prefix + 'data/' + key)
                    cnt = min(8, len(raw) // size)
                    vals = struct.unpack('<' + fmt * cnt, raw[:cnt * size])
                    sample = {"layer": k, "dtype": dtn,
                              "values": [round(x, 6) if isinstance(x, float) else x for x in vals]}
        else:
            layers.append({"name": k, "dtype": "scalar/meta", "shape": [], "params": 0,
                           "value": str(v)[:80]})
    print(json.dumps({"format": "pytorch_state_dict", "num_tensors": len(layers),
                      "total_params": total, "layers": layers, "sample": sample}))

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

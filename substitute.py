# -*- coding: utf-8 -*-
import hashlib
import subprocess
from time import time
from Crypto import Random
from Crypto.PublicKey import RSA
from pathlib import Path


def collision(file, prefix=None):
    '''MD5碰撞'''
    p = Path(file)  # .absolute()
    parent = p.parent  # 文件夹
    name = p.name.split('.')[0]  # 文件名
    suffixes = p.suffixes  # 全部后缀
    if not prefix:
        prefix = str(int(time()))  # 避免覆盖未备份的文件，丢失后无法还原
    file1 = parent.joinpath(prefix+'_'+name+'_1'+''.join(suffixes))
    file2 = parent.joinpath(prefix+'_'+name+'_2'+''.join(suffixes))
    file1 = file1.with_suffix('.key')
    file2 = file2.with_suffix('.key')
    cmd = ['fastcoll', file, '-q', '-o', str(file1), str(file2)]
    # print(cmd)
    run = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return run.returncode, file1, file2


def get_base(file='./key/key.base', with_block=False):
    path = Path(file)
    if path.is_file() and path.exists():
        with open(path, 'rb') as f:
            data = f.read()
    else:
        if not with_block:
            data = make_base(file)
        else:
            raise Exception(f'缺少 {file!r} 文件!!')
    return data


def make_base(file):
    '''生成一个主文件。这里是RSA公钥的生成方法，演示。'''
    g = Random.new().read
    k = RSA.generate(2048, g)
    b = k.exportKey()
    with open(file, 'wb+') as f:
        f.write(b)
    return b


def make_block(file='./key/key.base'):
    key1, key2 = make_key(file)
    base_size = Path(file).stat().st_size
    block1 = _make_block(key1, base_size)
    block2 = _make_block(key2, base_size)
    return md5(key1), block1, block2


def _make_block(key, base_size):
    size = Path(key).stat().st_size
    with open(key, 'rb') as f:
        f.seek(base_size, 0)
        block1 = f.read(size - base_size)
    with open(key.with_suffix('.block'), 'wb') as f:
        f.write(block1)
    return key.with_suffix('.block')


def make_key(base='./key/key.base'):
    get_base(base)   # 尝试获取，不存在时生成一个
    returncode, file1, file2 = collision(base)
    if not returncode:
        return file1, file2


def md5(file) -> str:
    with open(file, 'rb') as f:
        data = f.read()
    return _md5(data)


def _md5(_bytes) -> str:
    m = hashlib.md5()
    m.update(_bytes)
    return m.hexdigest()


def block_to_md5(block, base='./key/key.base'):
    data = get_base(base, with_block=True)
    with open(block, 'rb') as f1:
        r = _md5(data+f1.read())
    return r


if __name__ == '__main__':
    m, block1, block2 = make_block()
    b = block_to_md5(block1)
    print(m, b, m == b)

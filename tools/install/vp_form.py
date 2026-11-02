"""TTY form from the shared generated JSON Schema, not protocol templates.

This collects DTOs only. The authenticated API/compiler remains authoritative
for exact semantic validation, capability gates, secrets and application.
"""
from pathlib import Path
from vp_install import InstallError, require, read_regular, strict_json

FIELD_LABELS = {
    'id': '唯一标识（字母、数字、短横线）', 'name': '显示名称', 'enabled': '是否启用',
    'bind': '服务监听地址', 'address': '监听 IP 地址（公网开放需单独验收）',
    'port': '监听端口（必须未占用；不会自动开放防火墙）',
    'users': '授权用户', 'credentialRef': '已存在的凭据引用（不是密码或 UUID 原文）',
    'certificateRef': '已存在的服务器证书引用', 'privateKeyRef': '已存在的私钥引用',
    'serverName': '服务器域名 / SNI（应与证书匹配）', 'alpn': 'ALPN 协议列表',
    'path': '传输路径', 'host': 'Host 主机名', 'hosts': 'Host 主机名列表',
    'security': '安全层', 'transport': '传输层', 'cipher': '加密算法', 'flow': '流控类型',
    'shortIds': 'REALITY 短 ID 列表', 'handshakeTarget': 'REALITY 握手目标',
    'serverNames': '允许的服务器域名 / SNI', 'earlyData': '早期数据（不需要时选择不设置）',
}

def field_label(path):
    key = path.rsplit('.', 1)[-1]
    return FIELD_LABELS.get(key, key) + ' [' + path + ']'

class SchemaForm:
    def __init__(self, document, ask=input, say=print, credential_provider=None):
        self.defs = document.get('$defs', {})
        require(isinstance(self.defs, dict) and 'ServerListener' in self.defs, 'shared schema unavailable')
        self.ask, self.say = ask, say
        self.credential_provider = credential_provider

    def shape(self, schema):
        if '$ref' in schema:
            ref = schema['$ref']
            require(ref.startswith('#/$defs/') and ref[8:] in self.defs, 'unsupported schema reference')
            schema = self.defs[ref[8:]]
        # Generated schema supplements Rust-derived representation with stricter
        # shared allOf constraints. Prefer that shared authored shape for prompts.
        for extra in schema.get('allOf', []):
            if any(k in extra for k in ('properties', 'oneOf', 'anyOf', 'const')):
                schema = {**schema, **extra}
        return schema

    def collect(self, schema, path, seeds=None, depth=0):
        require(depth <= 16, 'schema nesting limit')
        schema = self.shape(schema)
        seeds = seeds or {}
        if path in seeds:
            # Only caller-provided UI selections, never authorization or certification.
            return seeds[path]
        if path.endswith('.credentialRef') and self.credential_provider is not None:
            return self.credential_provider(path)
        if 'const' in schema:
            return schema['const']
        options = schema.get('oneOf') or schema.get('anyOf')
        if options:
            choices = [self.shape(option) for option in options]
            chosen = None
            kind = seeds.get(path + '.kind')
            if kind:
                for choice in choices:
                    prop = choice.get('properties', {}).get('kind', {})
                    if prop.get('const') == kind or kind in prop.get('enum', []):
                        chosen = choice
                require(chosen is not None, 'selected preset is absent from shared schema; no substitution')
            if chosen is None:
                labels = [self.label(c) for c in choices]
                self.say(field_label(path) + ': ' + ', '.join(f'{i+1}={label}' for i,label in enumerate(labels)))
                raw = self.ask('请选择编号 / Choice number: ').strip()
                require(raw.isdigit() and 1 <= int(raw) <= len(choices), 'invalid schema choice')
                chosen = choices[int(raw)-1]
            return self.collect(chosen, path, seeds, depth+1)
        values = schema.get('enum')
        if values:
            if len(values) == 1:
                return values[0]
            self.say(field_label(path) + ': ' + ', '.join(f'{i+1}={v}' for i,v in enumerate(values)))
            raw = self.ask('请选择编号 / Choice number: ').strip()
            require(raw.isdigit() and 1 <= int(raw) <= len(values), 'invalid enum choice')
            return values[int(raw)-1]
        kind = schema.get('type')
        if isinstance(kind, list):
            return self.collect({'anyOf':[{**schema,'type':v} for v in kind]},path,seeds,depth+1)
        if kind == 'null':
            return None
        if kind == 'object' or 'properties' in schema:
            result = {}
            required = schema.get('required', [])
            for key, value in schema.get('properties', {}).items():
                if key not in required:
                    answer = self.ask(f'是否设置可选项 {field_label(path+"."+key)}? [y/N]: ').strip().lower()
                    if answer != 'y':
                        continue
                elif path+'.'+key not in seeds and key not in ('schemaVersion', 'kind'):
                    self.say('必填 / Required: ' + field_label(path+'.'+key))
                result[key] = self.collect(value, path+'.'+key, seeds, depth+1)
            return result
        if kind == 'array':
            minimum, maximum = schema.get('minItems', 0), min(schema.get('maxItems', 32), 32)
            raw = self.ask(f'{field_label(path)}: 数量 / number of items ({minimum}..{maximum}): ').strip()
            require(raw.isdigit() and minimum <= int(raw) <= maximum, 'invalid bounded array size')
            return [self.collect(schema['items'], f'{path}[{i}]', seeds, depth+1) for i in range(int(raw))]
        if kind == 'boolean':
            raw = self.ask(field_label(path)+' [是/否; true/false]: ').strip().lower()
            require(raw in ('true','false','是','否'), 'boolean must be explicit')
            return raw in ('true', '是')
        if kind == 'integer':
            raw = self.ask(field_label(path)+'（整数 / integer）: ').strip()
            require(raw.isdigit() and len(raw) <= 20, 'invalid integer')
            value = int(raw)
            require(schema.get('minimum', value) <= value <= schema.get('maximum', value), 'integer outside shared-schema bounds')
            return value
        if kind == 'string':
            hint = '（仅现有引用；不能粘贴密码或密钥）' if path.endswith('Ref') else ''
            value = self.ask(field_label(path)+hint+': ')
            require(len(value) <= 2048 and not any(ord(c)<32 for c in value), 'invalid/oversized text field')
            if path.endswith('credentialRef') or path.endswith('privateKeyRef') or path.endswith('passwordRef'):
                require(value.startswith('secret:'), 'vault reference required; raw secret input rejected')
            return value
        raise InstallError('当前向导尚未支持此共享字段形状；请反馈具体字段，未创建隧道 / unsupported shared-schema form shape')

    def label(self, schema):
        prop = schema.get('properties', {}).get('kind', {})
        label = prop.get('const') or (prop.get('enum') or [None])[0] or schema.get('type') or 'object'
        return str({'null': '不设置 / null', 'string': '文本 / string', 'object': '参数组 / object'}.get(label, label))

def listener_wizard(preset, schema_path=None, ask=input, say=print, credential_provider=None):
    require(preset['scope'] == 'required_public_baseline', 'Direct remains an explicit pending scope decision; no synthetic protocol')
    repo = Path(__file__).resolve().parents[2]
    file = Path(schema_path) if schema_path else repo/'contracts/schema/v1.schema.json'
    document = strict_json(read_regular(file, 2*1024*1024))
    form = SchemaForm(document,ask,say,credential_provider)
    seeds = {'listener.schemaVersion':1, 'listener.requirements':[preset['key']],
             'listener.protocol.kind':'proxy', 'listener.protocol.protocol.kind':preset['protocol'], 'listener.transport.kind':preset['transport'],
             'listener.security.kind':preset['security']}
    say(f"已选择：{preset['name']} · 协议 {preset['protocol']} / 传输 {preset['transport']} / 安全层 {preset['security']}")
    say('向导逐项收集必填字段，不要求手写 JSON；最终校验和应用由同一个管理 API 完成。')
    say('端口必须未占用；证书/私钥只能选择现有引用，不能在此粘贴秘密。')
    if credential_provider is not None:
        say('用户连接凭据从管理 API 库存选择或显式生成 UUID；不手填 SecretRef、不显示秘密。生成并不等于已应用。')
    else:
        say('此独立表单只接受已有用户凭据引用；不会本地生成秘密。')
    if preset['security'] == 'tls':
        say('TLS 需要已导入的匹配域名证书和私钥引用；当前向导不能自动申请 ACME 证书。')
    elif preset['security'] == 'reality':
        say('REALITY 需要已配置私钥引用与握手参数；当前向导不能自动生成生产密钥。')
    say('若没有这些引用，请先完成管理员的安全预配置；可随时 Ctrl-C 取消，不能假装已安装。')
    return form.collect({'$ref':'#/$defs/ServerListener'}, 'listener', seeds)

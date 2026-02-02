// Copyright 2019-2026 @pezkuwi/wasm-crypto authors & contributors
// SPDX-License-Identifier: Apache-2.0

// Direct wrapper around bizinikiwi WASM (compiled with wasm-bindgen externref)
// Uses bizinikiwi signing context for PezkuwiChain SR25519 signatures

import { wasmBytes } from '@pezkuwi/wasm-crypto-wasm';

export { packageInfo } from './packageInfo.js';

// WASM instance and memory
let wasm: Record<string, unknown> | null = null;
let cachedUint8ArrayMemory: Uint8Array | null = null;
let cachedTextDecoder: TextDecoder | null = null;
let _isReady = false;
let initPromise: Promise<boolean> | null = null;
let WASM_VECTOR_LEN = 0;

// Memory helpers
function getUint8ArrayMemory(): Uint8Array {
  if (cachedUint8ArrayMemory === null || cachedUint8ArrayMemory.byteLength === 0) {
    cachedUint8ArrayMemory = new Uint8Array((wasm!['memory'] as WebAssembly.Memory).buffer);
  }
  return cachedUint8ArrayMemory;
}

function getStringFromWasm(ptr: number, len: number): string {
  if (!cachedTextDecoder) {
    cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
    cachedTextDecoder.decode();
  }
  ptr = ptr >>> 0;
  return cachedTextDecoder.decode(getUint8ArrayMemory().subarray(ptr, ptr + len));
}

function getArrayU8FromWasm(ptr: number, len: number): Uint8Array {
  ptr = ptr >>> 0;
  return getUint8ArrayMemory().subarray(ptr / 1, ptr / 1 + len);
}

function passArray8ToWasm(arg: Uint8Array, malloc: (size: number, align: number) => number): number {
  const ptr = malloc(arg.length * 1, 1) >>> 0;
  getUint8ArrayMemory().set(arg, ptr / 1);
  WASM_VECTOR_LEN = arg.length;
  return ptr;
}

// Externref table helpers
function addToExternrefTable(obj: unknown): number {
  const idx = (wasm!['__externref_table_alloc'] as () => number)();
  (wasm!['__wbindgen_externrefs'] as WebAssembly.Table).set(idx, obj);
  return idx;
}

function takeFromExternrefTable(idx: number): unknown {
  const value = (wasm!['__wbindgen_externrefs'] as WebAssembly.Table).get(idx);
  (wasm!['__externref_table_dealloc'] as (idx: number) => void)(idx);
  return value;
}

function isLikeNone(x: unknown): boolean {
  return x === undefined || x === null;
}

function handleError<T extends unknown[]>(f: (...args: T) => unknown, args: IArguments): unknown {
  try {
    return f.apply(null, args as unknown as T);
  } catch (e) {
    const idx = addToExternrefTable(e);
    (wasm!['__wbindgen_exn_store'] as (idx: number) => void)(idx);
    return undefined;
  }
}

// WASM imports - matches pezkuwi_wasm_crypto.js __wbg_get_imports()
function createImports(): WebAssembly.Imports {
  const import0: Record<string, unknown> = {
    __proto__: null,

    __wbg___wbindgen_is_function_0095a73b8b156f76: function(arg0: unknown): boolean {
      return typeof(arg0) === 'function';
    },

    __wbg___wbindgen_is_object_5ae8e5880f2c1fbd: function(arg0: unknown): boolean {
      const val = arg0;
      return typeof(val) === 'object' && val !== null;
    },

    __wbg___wbindgen_is_string_cd444516edc5b180: function(arg0: unknown): boolean {
      return typeof(arg0) === 'string';
    },

    __wbg___wbindgen_is_undefined_9e4d92534c42d778: function(arg0: unknown): boolean {
      return arg0 === undefined;
    },

    __wbg___wbindgen_throw_be289d5034ed271b: function(arg0: number, arg1: number): never {
      throw new Error(getStringFromWasm(arg0, arg1));
    },

    __wbg_call_389efe28435a9388: function(): unknown {
      return handleError(function(arg0: { call: (thisArg: unknown) => unknown }, arg1: unknown) {
        return arg0.call(arg1);
      }, arguments);
    },

    __wbg_call_4708e0c13bdc8e95: function(): unknown {
      return handleError(function(arg0: { call: (thisArg: unknown, arg: unknown) => unknown }, arg1: unknown, arg2: unknown) {
        return arg0.call(arg1, arg2);
      }, arguments);
    },

    __wbg_crypto_86f2631e91b51511: function(arg0: { crypto?: Crypto }): Crypto | undefined {
      return arg0.crypto;
    },

    __wbg_getRandomValues_b3f15fcbfabb0f8b: function(): void {
      return handleError(function(arg0: { getRandomValues: (arr: Uint8Array) => void }, arg1: Uint8Array) {
        arg0.getRandomValues(arg1);
      }, arguments) as void;
    },

    __wbg_length_32ed9a279acd054c: function(arg0: { length: number }): number {
      return arg0.length;
    },

    __wbg_msCrypto_d562bbe83e0d4b91: function(arg0: { msCrypto?: unknown }): unknown {
      return arg0.msCrypto;
    },

    __wbg_new_no_args_1c7c842f08d00ebb: function(arg0: number, arg1: number): Function {
      return new Function(getStringFromWasm(arg0, arg1));
    },

    __wbg_new_with_length_a2c39cbe88fd8ff1: function(arg0: number): Uint8Array {
      return new Uint8Array(arg0 >>> 0);
    },

    __wbg_node_e1f24f89a7336c2e: function(arg0: { node?: unknown }): unknown {
      return arg0.node;
    },

    __wbg_process_3975fd6c72f520aa: function(arg0: { process?: unknown }): unknown {
      return arg0.process;
    },

    __wbg_prototypesetcall_bdcdcc5842e4d77d: function(arg0: number, arg1: number, arg2: Uint8Array): void {
      Uint8Array.prototype.set.call(getArrayU8FromWasm(arg0, arg1), arg2);
    },

    __wbg_randomFillSync_f8c153b79f285817: function(): void {
      return handleError(function(arg0: { randomFillSync: (arr: Uint8Array) => void }, arg1: Uint8Array) {
        arg0.randomFillSync(arg1);
      }, arguments) as void;
    },

    __wbg_require_b74f47fc2d022fd6: function(): unknown {
      return handleError(function() {
        return typeof module !== 'undefined' ? (module as NodeModule & { require?: unknown }).require : undefined;
      }, arguments);
    },

    __wbg_static_accessor_GLOBAL_12837167ad935116: function(): number {
      const ret = typeof global === 'undefined' ? null : global;
      return isLikeNone(ret) ? 0 : addToExternrefTable(ret);
    },

    __wbg_static_accessor_GLOBAL_THIS_e628e89ab3b1c95f: function(): number {
      const ret = typeof globalThis === 'undefined' ? null : globalThis;
      return isLikeNone(ret) ? 0 : addToExternrefTable(ret);
    },

    __wbg_static_accessor_SELF_a621d3dfbb60d0ce: function(): number {
      const ret = typeof self === 'undefined' ? null : self;
      return isLikeNone(ret) ? 0 : addToExternrefTable(ret);
    },

    __wbg_static_accessor_WINDOW_f8727f0cf888e0bd: function(): number {
      const ret = typeof window === 'undefined' ? null : window;
      return isLikeNone(ret) ? 0 : addToExternrefTable(ret);
    },

    __wbg_subarray_a96e1fef17ed23cb: function(arg0: Uint8Array, arg1: number, arg2: number): Uint8Array {
      return arg0.subarray(arg1 >>> 0, arg2 >>> 0);
    },

    __wbg_versions_4e31226f5e8dc909: function(arg0: { versions?: unknown }): unknown {
      return arg0.versions;
    },

    __wbindgen_cast_0000000000000001: function(arg0: number, arg1: number): Uint8Array {
      return getArrayU8FromWasm(arg0, arg1);
    },

    __wbindgen_cast_0000000000000002: function(arg0: number, arg1: number): string {
      return getStringFromWasm(arg0, arg1);
    },

    __wbindgen_init_externref_table: function(): void {
      const table = wasm!['__wbindgen_externrefs'] as WebAssembly.Table;
      const offset = table.grow(4);
      table.set(0, undefined);
      table.set(offset + 0, undefined);
      table.set(offset + 1, null);
      table.set(offset + 2, true);
      table.set(offset + 3, false);
    },
  };

  return {
    __proto__: null,
    './pezkuwi_wasm_crypto_bg.js': import0,
  } as unknown as WebAssembly.Imports;
}

// Initialize WASM
async function initWasm(): Promise<boolean> {
  if (_isReady) return true;

  try {
    // wasmBytes is already decompressed by @pezkuwi/wasm-crypto-wasm
    const imports = createImports();
    const result = await WebAssembly.instantiate(wasmBytes as BufferSource, imports);

    wasm = (result as WebAssembly.WebAssemblyInstantiatedSource).instance.exports as Record<string, unknown>;

    // Initialize the module
    if (typeof wasm['__wbindgen_start'] === 'function') {
      (wasm['__wbindgen_start'] as () => void)();
    }

    _isReady = true;
    return true;
  } catch (error) {
    console.error('FATAL: Unable to initialize @pezkuwi/wasm-crypto:', (error as Error).message);
    return false;
  }
}

// Public API - backward compatible with @polkadot/wasm-crypto

export const bridge = {
  wasm: null as unknown,
  type: 'wasm' as const
};

export function isReady(): boolean {
  return _isReady;
}

export async function waitReady(): Promise<boolean> {
  if (!initPromise) {
    initPromise = initWasm();
  }
  return initPromise;
}

// Get signing context (should return "bizinikiwi")
export function getSigningContext(): string {
  if (!wasm) throw new Error('WASM not initialized');
  const ret = (wasm['get_signing_context'] as () => [number, number])();
  const str = getStringFromWasm(ret[0], ret[1]);
  (wasm['__wbindgen_free'] as (ptr: number, len: number, align: number) => void)(ret[0], ret[1], 1);
  return str;
}

// SR25519 - Uses bizinikiwi signing context

export function sr25519KeypairFromSeed(seed: Uint8Array): Uint8Array {
  if (!wasm) throw new Error('WASM not initialized');
  const ptr0 = passArray8ToWasm(seed, wasm['__wbindgen_malloc'] as (size: number, align: number) => number);
  const len0 = WASM_VECTOR_LEN;
  const ret = (wasm['sr25519_keypair_from_seed'] as (ptr: number, len: number) => [number, number, number, number])(ptr0, len0);
  if (ret[3]) {
    throw takeFromExternrefTable(ret[2]) as Error;
  }
  const v2 = getArrayU8FromWasm(ret[0], ret[1]).slice();
  (wasm['__wbindgen_free'] as (ptr: number, len: number, align: number) => void)(ret[0], ret[1] * 1, 1);
  return v2;
}

export function sr25519Sign(publicKey: Uint8Array, secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  if (!wasm) throw new Error('WASM not initialized');
  const ptr0 = passArray8ToWasm(publicKey, wasm['__wbindgen_malloc'] as (size: number, align: number) => number);
  const len0 = WASM_VECTOR_LEN;
  const ptr1 = passArray8ToWasm(secretKey, wasm['__wbindgen_malloc'] as (size: number, align: number) => number);
  const len1 = WASM_VECTOR_LEN;
  const ptr2 = passArray8ToWasm(message, wasm['__wbindgen_malloc'] as (size: number, align: number) => number);
  const len2 = WASM_VECTOR_LEN;
  const ret = (wasm['sr25519_sign'] as (p0: number, l0: number, p1: number, l1: number, p2: number, l2: number) => [number, number, number, number])(ptr0, len0, ptr1, len1, ptr2, len2);
  if (ret[3]) {
    throw takeFromExternrefTable(ret[2]) as Error;
  }
  const v4 = getArrayU8FromWasm(ret[0], ret[1]).slice();
  (wasm['__wbindgen_free'] as (ptr: number, len: number, align: number) => void)(ret[0], ret[1] * 1, 1);
  return v4;
}

export function sr25519Verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  if (!wasm) throw new Error('WASM not initialized');
  const ptr0 = passArray8ToWasm(signature, wasm['__wbindgen_malloc'] as (size: number, align: number) => number);
  const len0 = WASM_VECTOR_LEN;
  const ptr1 = passArray8ToWasm(message, wasm['__wbindgen_malloc'] as (size: number, align: number) => number);
  const len1 = WASM_VECTOR_LEN;
  const ptr2 = passArray8ToWasm(publicKey, wasm['__wbindgen_malloc'] as (size: number, align: number) => number);
  const len2 = WASM_VECTOR_LEN;
  const ret = (wasm['sr25519_verify'] as (p0: number, l0: number, p1: number, l1: number, p2: number, l2: number) => number)(ptr0, len0, ptr1, len1, ptr2, len2);
  return ret !== 0;
}

// BIP39 JavaScript implementations (not in bizinikiwi WASM)
// Using minimal implementations compatible with original wasm-crypto

import { sha256 as nobleSha256 } from '@noble/hashes/sha256';
import { sha512 as nobleSha512 } from '@noble/hashes/sha512';
import { pbkdf2 as noblePbkdf2 } from '@noble/hashes/pbkdf2';
import { blake2b as nobleBlake2b } from '@noble/hashes/blake2b';
import { hmac } from '@noble/hashes/hmac';
import { keccak_256, keccak_512 } from '@noble/hashes/sha3';
import { scrypt as nobleScrypt } from '@noble/hashes/scrypt';

function normalizeString(str: string): string {
  return (str || '').normalize('NFKD');
}

// Basic validation - check word count only
// Full validation with wordlist happens in util-crypto's JS fallback
export function bip39Validate(phrase: string): boolean {
  try {
    const words = normalizeString(phrase).split(' ');
    return [12, 15, 18, 21, 24].includes(words.length);
  } catch {
    return false;
  }
}

// BIP39 English wordlist
const BIP39_WORDLIST = 'abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse|access|accident|account|accuse|achieve|acid|acoustic|acquire|across|act|action|actor|actress|actual|adapt|add|addict|address|adjust|admit|adult|advance|advice|aerobic|affair|afford|afraid|again|age|agent|agree|ahead|aim|air|airport|aisle|alarm|album|alcohol|alert|alien|all|alley|allow|almost|alone|alpha|already|also|alter|always|amateur|amazing|among|amount|amused|analyst|anchor|ancient|anger|angle|angry|animal|ankle|announce|annual|another|answer|antenna|antique|anxiety|any|apart|apology|appear|apple|approve|april|arch|arctic|area|arena|argue|arm|armed|armor|army|around|arrange|arrest|arrive|arrow|art|artefact|artist|artwork|ask|aspect|assault|asset|assist|assume|asthma|athlete|atom|attack|attend|attitude|attract|auction|audit|august|aunt|author|auto|autumn|average|avocado|avoid|awake|aware|away|awesome|awful|awkward|axis|baby|bachelor|bacon|badge|bag|balance|balcony|ball|bamboo|banana|banner|bar|barely|bargain|barrel|base|basic|basket|battle|beach|bean|beauty|because|become|beef|before|begin|behave|behind|believe|below|belt|bench|benefit|best|betray|better|between|beyond|bicycle|bid|bike|bind|biology|bird|birth|bitter|black|blade|blame|blanket|blast|bleak|bless|blind|blood|blossom|blouse|blue|blur|blush|board|boat|body|boil|bomb|bone|bonus|book|boost|border|boring|borrow|boss|bottom|bounce|box|boy|bracket|brain|brand|brass|brave|bread|breeze|brick|bridge|brief|bright|bring|brisk|broccoli|broken|bronze|broom|brother|brown|brush|bubble|buddy|budget|buffalo|build|bulb|bulk|bullet|bundle|bunker|burden|burger|burst|bus|business|busy|butter|buyer|buzz|cabbage|cabin|cable|cactus|cage|cake|call|calm|camera|camp|can|canal|cancel|candy|cannon|canoe|canvas|canyon|capable|capital|captain|car|carbon|card|cargo|carpet|carry|cart|case|cash|casino|castle|casual|cat|catalog|catch|category|cattle|caught|cause|caution|cave|ceiling|celery|cement|census|century|cereal|certain|chair|chalk|champion|change|chaos|chapter|charge|chase|chat|cheap|check|cheese|chef|cherry|chest|chicken|chief|child|chimney|choice|choose|chronic|chuckle|chunk|churn|cigar|cinnamon|circle|citizen|city|civil|claim|clap|clarify|claw|clay|clean|clerk|clever|click|client|cliff|climb|clinic|clip|clock|clog|close|cloth|cloud|clown|club|clump|cluster|clutch|coach|coast|coconut|code|coffee|coil|coin|collect|color|column|combine|come|comfort|comic|common|company|concert|conduct|confirm|congress|connect|consider|control|convince|cook|cool|copper|copy|coral|core|corn|correct|cost|cotton|couch|country|couple|course|cousin|cover|coyote|crack|cradle|craft|cram|crane|crash|crater|crawl|crazy|cream|credit|creek|crew|cricket|crime|crisp|critic|crop|cross|crouch|crowd|crucial|cruel|cruise|crumble|crunch|crush|cry|crystal|cube|culture|cup|cupboard|curious|current|curtain|curve|cushion|custom|cute|cycle|dad|damage|damp|dance|danger|daring|dash|daughter|dawn|day|deal|debate|debris|decade|december|decide|decline|decorate|decrease|deer|defense|define|defy|degree|delay|deliver|demand|demise|denial|dentist|deny|depart|depend|deposit|depth|deputy|derive|describe|desert|design|desk|despair|destroy|detail|detect|develop|device|devote|diagram|dial|diamond|diary|dice|diesel|diet|differ|digital|dignity|dilemma|dinner|dinosaur|direct|dirt|disagree|discover|disease|dish|dismiss|disorder|display|distance|divert|divide|divorce|dizzy|doctor|document|dog|doll|dolphin|domain|donate|donkey|donor|door|dose|double|dove|draft|dragon|drama|drastic|draw|dream|dress|drift|drill|drink|drip|drive|drop|drum|dry|duck|dumb|dune|during|dust|dutch|duty|dwarf|dynamic|eager|eagle|early|earn|earth|easily|east|easy|echo|ecology|economy|edge|edit|educate|effort|egg|eight|either|elbow|elder|electric|elegant|element|elephant|elevator|elite|else|embark|embody|embrace|emerge|emotion|employ|empower|empty|enable|enact|end|endless|endorse|enemy|energy|enforce|engage|engine|enhance|enjoy|enlist|enough|enrich|enroll|ensure|enter|entire|entry|envelope|episode|equal|equip|era|erase|erode|erosion|error|erupt|escape|essay|essence|estate|eternal|ethics|evidence|evil|evoke|evolve|exact|example|excess|exchange|excite|exclude|excuse|execute|exercise|exhaust|exhibit|exile|exist|exit|exotic|expand|expect|expire|explain|expose|express|extend|extra|eye|eyebrow|fabric|face|faculty|fade|faint|faith|fall|false|fame|family|famous|fan|fancy|fantasy|farm|fashion|fat|fatal|father|fatigue|fault|favorite|feature|february|federal|fee|feed|feel|female|fence|festival|fetch|fever|few|fiber|fiction|field|figure|file|film|filter|final|find|fine|finger|finish|fire|firm|first|fiscal|fish|fit|fitness|fix|flag|flame|flash|flat|flavor|flee|flight|flip|float|flock|floor|flower|fluid|flush|fly|foam|focus|fog|foil|fold|follow|food|foot|force|forest|forget|fork|fortune|forum|forward|fossil|foster|found|fox|fragile|frame|frequent|fresh|friend|fringe|frog|front|frost|frown|frozen|fruit|fuel|fun|funny|furnace|fury|future|gadget|gain|galaxy|gallery|game|gap|garage|garbage|garden|garlic|garment|gas|gasp|gate|gather|gauge|gaze|general|genius|genre|gentle|genuine|gesture|ghost|giant|gift|giggle|ginger|giraffe|girl|give|glad|glance|glare|glass|glide|glimpse|globe|gloom|glory|glove|glow|glue|goat|goddess|gold|good|goose|gorilla|gospel|gossip|govern|gown|grab|grace|grain|grant|grape|grass|gravity|great|green|grid|grief|grit|grocery|group|grow|grunt|guard|guess|guide|guilt|guitar|gun|gym|habit|hair|half|hammer|hamster|hand|happy|harbor|hard|harsh|harvest|hat|have|hawk|hazard|head|health|heart|heavy|hedgehog|height|hello|helmet|help|hen|hero|hidden|high|hill|hint|hip|hire|history|hobby|hockey|hold|hole|holiday|hollow|home|honey|hood|hope|horn|horror|horse|hospital|host|hotel|hour|hover|hub|huge|human|humble|humor|hundred|hungry|hunt|hurdle|hurry|hurt|husband|hybrid|ice|icon|idea|identify|idle|ignore|ill|illegal|illness|image|imitate|immense|immune|impact|impose|improve|impulse|inch|include|income|increase|index|indicate|indoor|industry|infant|inflict|inform|inhale|inherit|initial|inject|injury|inmate|inner|innocent|input|inquiry|insane|insect|inside|inspire|install|intact|interest|into|invest|invite|involve|iron|island|isolate|issue|item|ivory|jacket|jaguar|jar|jazz|jealous|jeans|jelly|jewel|job|join|joke|journey|joy|judge|juice|jump|jungle|junior|junk|just|kangaroo|keen|keep|ketchup|key|kick|kid|kidney|kind|kingdom|kiss|kit|kitchen|kite|kitten|kiwi|knee|knife|knock|know|lab|label|labor|ladder|lady|lake|lamp|language|laptop|large|later|latin|laugh|laundry|lava|law|lawn|lawsuit|layer|lazy|leader|leaf|learn|leave|lecture|left|leg|legal|legend|leisure|lemon|lend|length|lens|leopard|lesson|letter|level|liar|liberty|library|license|life|lift|light|like|limb|limit|link|lion|liquid|list|little|live|lizard|load|loan|lobster|local|lock|logic|lonely|long|loop|lottery|loud|lounge|love|loyal|lucky|luggage|lumber|lunar|lunch|luxury|lyrics|machine|mad|magic|magnet|maid|mail|main|major|make|mammal|man|manage|mandate|mango|mansion|manual|maple|marble|march|margin|marine|market|marriage|mask|mass|master|match|material|math|matrix|matter|maximum|maze|meadow|mean|measure|meat|mechanic|medal|media|melody|melt|member|memory|mention|menu|mercy|merge|merit|merry|mesh|message|metal|method|middle|midnight|milk|million|mimic|mind|minimum|minor|minute|miracle|mirror|misery|miss|mistake|mix|mixed|mixture|mobile|model|modify|mom|moment|monitor|monkey|monster|month|moon|moral|more|morning|mosquito|mother|motion|motor|mountain|mouse|move|movie|much|muffin|mule|multiply|muscle|museum|mushroom|music|must|mutual|myself|mystery|myth|naive|name|napkin|narrow|nasty|nation|nature|near|neck|need|negative|neglect|neither|nephew|nerve|nest|net|network|neutral|never|news|next|nice|night|noble|noise|nominee|noodle|normal|north|nose|notable|note|nothing|notice|novel|now|nuclear|number|nurse|nut|oak|obey|object|oblige|obscure|observe|obtain|obvious|occur|ocean|october|odor|off|offer|office|often|oil|okay|old|olive|olympic|omit|once|one|onion|online|only|open|opera|opinion|oppose|option|orange|orbit|orchard|order|ordinary|organ|orient|original|orphan|ostrich|other|outdoor|outer|output|outside|oval|oven|over|own|owner|oxygen|oyster|ozone|pact|paddle|page|pair|palace|palm|panda|panel|panic|panther|paper|parade|parent|park|parrot|party|pass|patch|path|patient|patrol|pattern|pause|pave|payment|peace|peanut|pear|peasant|pelican|pen|penalty|pencil|people|pepper|perfect|permit|person|pet|phone|photo|phrase|physical|piano|picnic|picture|piece|pig|pigeon|pill|pilot|pink|pioneer|pipe|pistol|pitch|pizza|place|planet|plastic|plate|play|please|pledge|pluck|plug|plunge|poem|poet|point|polar|pole|police|pond|pony|pool|popular|portion|position|possible|post|potato|pottery|poverty|powder|power|practice|praise|predict|prefer|prepare|present|pretty|prevent|price|pride|primary|print|priority|prison|private|prize|problem|process|produce|profit|program|project|promote|proof|property|prosper|protect|proud|provide|public|pudding|pull|pulp|pulse|pumpkin|punch|pupil|puppy|purchase|purity|purpose|purse|push|put|puzzle|pyramid|quality|quantum|quarter|question|quick|quit|quiz|quote|rabbit|raccoon|race|rack|radar|radio|rail|rain|raise|rally|ramp|ranch|random|range|rapid|rare|rate|rather|raven|raw|razor|ready|real|reason|rebel|rebuild|recall|receive|recipe|record|recycle|reduce|reflect|reform|refuse|region|regret|regular|reject|relax|release|relief|rely|remain|remember|remind|remove|render|renew|rent|reopen|repair|repeat|replace|report|require|rescue|resemble|resist|resource|response|result|retire|retreat|return|reunion|reveal|review|reward|rhythm|rib|ribbon|rice|rich|ride|ridge|rifle|right|rigid|ring|riot|ripple|risk|ritual|rival|river|road|roast|robot|robust|rocket|romance|roof|rookie|room|rose|rotate|rough|round|route|royal|rubber|rude|rug|rule|run|runway|rural|sad|saddle|sadness|safe|sail|salad|salmon|salon|salt|salute|same|sample|sand|satisfy|satoshi|sauce|sausage|save|say|scale|scan|scare|scatter|scene|scheme|school|science|scissors|scorpion|scout|scrap|screen|script|scrub|sea|search|season|seat|second|secret|section|security|seed|seek|segment|select|sell|seminar|senior|sense|sentence|series|service|session|settle|setup|seven|shadow|shaft|shallow|share|shed|shell|sheriff|shield|shift|shine|ship|shiver|shock|shoe|shoot|shop|short|shoulder|shove|shrimp|shrug|shuffle|shy|sibling|sick|side|siege|sight|sign|silent|silk|silly|silver|similar|simple|since|sing|siren|sister|situate|six|size|skate|sketch|ski|skill|skin|skirt|skull|slab|slam|sleep|slender|slice|slide|slight|slim|slogan|slot|slow|slush|small|smart|smile|smoke|smooth|snack|snake|snap|sniff|snow|soap|soccer|social|sock|soda|soft|solar|soldier|solid|solution|solve|someone|song|soon|sorry|sort|soul|sound|soup|source|south|space|spare|spatial|spawn|speak|special|speed|spell|spend|sphere|spice|spider|spike|spin|spirit|split|spoil|sponsor|spoon|sport|spot|spray|spread|spring|spy|square|squeeze|squirrel|stable|stadium|staff|stage|stairs|stamp|stand|start|state|stay|steak|steel|stem|step|stereo|stick|still|sting|stock|stomach|stone|stool|story|stove|strategy|street|strike|strong|struggle|student|stuff|stumble|style|subject|submit|subway|success|such|sudden|suffer|sugar|suggest|suit|summer|sun|sunny|sunset|super|supply|supreme|sure|surface|surge|surprise|surround|survey|suspect|sustain|swallow|swamp|swap|swarm|swear|sweet|swift|swim|swing|switch|sword|symbol|symptom|syrup|system|table|tackle|tag|tail|talent|talk|tank|tape|target|task|taste|tattoo|taxi|teach|team|tell|ten|tenant|tennis|tent|term|test|text|thank|that|theme|then|theory|there|they|thing|this|thought|three|thrive|throw|thumb|thunder|ticket|tide|tiger|tilt|timber|time|tiny|tip|tired|tissue|title|toast|tobacco|today|toddler|toe|together|toilet|token|tomato|tomorrow|tone|tongue|tonight|tool|tooth|top|topic|topple|torch|tornado|tortoise|toss|total|tourist|toward|tower|town|toy|track|trade|traffic|tragic|train|transfer|trap|trash|travel|tray|treat|tree|trend|trial|tribe|trick|trigger|trim|trip|trophy|trouble|truck|true|truly|trumpet|trust|truth|try|tube|tuition|tumble|tuna|tunnel|turkey|turn|turtle|twelve|twenty|twice|twin|twist|two|type|typical|ugly|umbrella|unable|unaware|uncle|uncover|under|undo|unfair|unfold|unhappy|uniform|unique|unit|universe|unknown|unlock|until|unusual|unveil|update|upgrade|uphold|upon|upper|upset|urban|urge|usage|use|used|useful|useless|usual|utility|vacant|vacuum|vague|valid|valley|valve|van|vanish|vapor|various|vast|vault|vehicle|velvet|vendor|venture|venue|verb|verify|version|very|vessel|veteran|viable|vibrant|vicious|victory|video|view|village|vintage|violin|virtual|virus|visa|visit|visual|vital|vivid|vocal|voice|void|volcano|volume|vote|voyage|wage|wagon|wait|walk|wall|walnut|want|warfare|warm|warrior|wash|wasp|waste|water|wave|way|wealth|weapon|wear|weasel|weather|web|wedding|weekend|weird|welcome|west|wet|whale|what|wheat|wheel|when|where|whip|whisper|wide|width|wife|wild|will|win|window|wine|wing|wink|winner|winter|wire|wisdom|wise|wish|witness|wolf|woman|wonder|wood|wool|word|work|world|worry|worth|wrap|wreck|wrestle|wrist|write|wrong|yard|year|yellow|you|young|youth|zebra|zero|zone|zoo'.split('|');

function binaryToByte(bin: string): number {
  return parseInt(bin, 2);
}

function bytesToBinary(bytes: number[]): string {
  return bytes.map((x) => x.toString(2).padStart(8, '0')).join('');
}

function deriveChecksumBits(entropyBuffer: Uint8Array): string {
  const hash = nobleSha256(entropyBuffer);
  return bytesToBinary(Array.from(hash)).slice(0, (entropyBuffer.length * 8) / 32);
}

export function bip39Generate(_words: 12 | 15 | 18 | 21 | 24): string {
  throw new Error('bip39Generate: use @pezkuwi/util-crypto mnemonicGenerate instead');
}

export function bip39ToEntropy(phrase: string): Uint8Array {
  const words = normalizeString(phrase).split(' ');
  if (words.length % 3 !== 0) {
    throw new Error('Invalid mnemonic');
  }
  // convert word indices to 11 bit binary strings
  const bits = words
    .map((word) => {
      const index = BIP39_WORDLIST.indexOf(word);
      if (index === -1) {
        throw new Error('Invalid mnemonic');
      }
      return index.toString(2).padStart(11, '0');
    })
    .join('');
  // split the binary string into ENT/CS
  const dividerIndex = Math.floor(bits.length / 33) * 32;
  const entropyBits = bits.slice(0, dividerIndex);
  const checksumBits = bits.slice(dividerIndex);
  // calculate the checksum and compare
  const matched = entropyBits.match(/(.{1,8})/g);
  const entropyBytes = matched?.map(binaryToByte);
  if (!entropyBytes || (entropyBytes.length % 4 !== 0) || (entropyBytes.length < 16) || (entropyBytes.length > 32)) {
    throw new Error('Invalid entropy');
  }
  const entropy = new Uint8Array(entropyBytes);
  if (deriveChecksumBits(entropy) !== checksumBits) {
    throw new Error('Invalid mnemonic checksum');
  }
  return entropy;
}

export function bip39ToMiniSecret(phrase: string, password: string): Uint8Array {
  // Substrate uses entropy-based derivation (not BIP39's mnemonic string PBKDF2)
  const entropy = bip39ToEntropy(phrase);
  const salt = new TextEncoder().encode(`mnemonic${normalizeString(password)}`);
  // PBKDF2 on the entropy, not the mnemonic string
  return noblePbkdf2(nobleSha512, entropy, salt, { c: 2048, dkLen: 64 }).slice(0, 32);
}

export function bip39ToSeed(phrase: string, password: string): Uint8Array {
  const salt = new TextEncoder().encode(`mnemonic${normalizeString(password)}`);
  const input = new TextEncoder().encode(normalizeString(phrase));
  return noblePbkdf2(nobleSha256, input, salt, { c: 2048, dkLen: 64 });
}

export function ed25519KeypairFromSeed(_seed: Uint8Array): Uint8Array {
  throw new Error('ed25519KeypairFromSeed not yet implemented');
}

export function ed25519Sign(_publicKey: Uint8Array, _secretKey: Uint8Array, _message: Uint8Array): Uint8Array {
  throw new Error('ed25519Sign not yet implemented');
}

export function ed25519Verify(_signature: Uint8Array, _message: Uint8Array, _publicKey: Uint8Array): boolean {
  throw new Error('ed25519Verify not yet implemented');
}

export function sr25519Agree(_publicKey: Uint8Array, _secretKey: Uint8Array): Uint8Array {
  throw new Error('sr25519Agree not yet implemented');
}

export function sr25519DeriveKeypairHard(_pair: Uint8Array, _cc: Uint8Array): Uint8Array {
  throw new Error('sr25519DeriveKeypairHard not yet implemented');
}

export function sr25519DeriveKeypairSoft(_pair: Uint8Array, _cc: Uint8Array): Uint8Array {
  throw new Error('sr25519DeriveKeypairSoft not yet implemented');
}

export function sr25519DerivePublicSoft(_publicKey: Uint8Array, _cc: Uint8Array): Uint8Array {
  throw new Error('sr25519DerivePublicSoft not yet implemented');
}

export function vrfSign(_secretKey: Uint8Array, _context: Uint8Array, _message: Uint8Array, _extra: Uint8Array): Uint8Array {
  throw new Error('vrfSign not yet implemented');
}

export function vrfVerify(_publicKey: Uint8Array, _context: Uint8Array, _message: Uint8Array, _extra: Uint8Array, _outAndProof: Uint8Array): boolean {
  throw new Error('vrfVerify not yet implemented');
}

export function secp256k1FromSeed(_seed: Uint8Array): Uint8Array {
  throw new Error('secp256k1FromSeed not yet implemented');
}

export function secp256k1Compress(_publicKey: Uint8Array): Uint8Array {
  throw new Error('secp256k1Compress not yet implemented');
}

export function secp256k1Expand(_publicKey: Uint8Array): Uint8Array {
  throw new Error('secp256k1Expand not yet implemented');
}

export function secp256k1Recover(_msgHash: Uint8Array, _signature: Uint8Array, _recoveryId: number): Uint8Array {
  throw new Error('secp256k1Recover not yet implemented');
}

export function secp256k1Sign(_msgHash: Uint8Array, _secretKey: Uint8Array): Uint8Array {
  throw new Error('secp256k1Sign not yet implemented');
}

export function blake2b(data: Uint8Array, key: Uint8Array, size: number): Uint8Array {
  // size is already in bytes (passed by util-crypto's blake2AsU8a)
  if (key && key.length > 0) {
    return nobleBlake2b(data, { dkLen: size, key });
  }
  return nobleBlake2b(data, { dkLen: size });
}

export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(nobleSha256, key, data);
}

export function hmacSha512(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(nobleSha512, key, data);
}

export function keccak256(data: Uint8Array): Uint8Array {
  return keccak_256(data);
}

export function keccak512(data: Uint8Array): Uint8Array {
  return keccak_512(data);
}

export function pbkdf2(data: Uint8Array, salt: Uint8Array, rounds: number): Uint8Array {
  return noblePbkdf2(nobleSha512, data, salt, { c: rounds, dkLen: 64 });
}

export function scrypt(password: Uint8Array, salt: Uint8Array, log2n: number, r: number, p: number): Uint8Array {
  // Convert log2n to N (cost parameter)
  // log2n is log2(N), so N = 2^log2n
  const N = 1 << log2n;
  return nobleScrypt(password, salt, { N, r, p, dkLen: 64 });
}

export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

export function sha512(data: Uint8Array): Uint8Array {
  return nobleSha512(data);
}

// xxhash64 implementation
const P64_1 = BigInt('11400714785074694791');
const P64_2 = BigInt('14029467366897019727');
const P64_3 = BigInt('1609587929392839161');
const P64_4 = BigInt('9650029242287828579');
const P64_5 = BigInt('2870177450012600261');
const U64 = BigInt('0xffffffffffffffff');
const _0n = BigInt(0);
const _1n = BigInt(1);
const _7n = BigInt(7);
const _11n = BigInt(11);
const _12n = BigInt(12);
const _16n = BigInt(16);
const _18n = BigInt(18);
const _23n = BigInt(23);
const _27n = BigInt(27);
const _29n = BigInt(29);
const _31n = BigInt(31);
const _32n = BigInt(32);
const _33n = BigInt(33);
const _64n = BigInt(64);
const _256n = BigInt(256);

function rotl(a: bigint, b: bigint): bigint {
  const c = a & U64;
  return ((c << b) | (c >> (_64n - b))) & U64;
}

function fromU8a(u8a: Uint8Array, p: number, count: number): bigint {
  const bigints = new Array<bigint>(count);
  let offset = 0;
  for (let i = 0; i < count; i++, offset += 2) {
    bigints[i] = BigInt(u8a[p + offset] | (u8a[p + 1 + offset] << 8));
  }
  let result = _0n;
  for (let i = count - 1; i >= 0; i--) {
    result = (result << _16n) + bigints[i];
  }
  return result;
}

function xxhashInit(seed: bigint, input: Uint8Array): { seed: bigint; u8a: Uint8Array; u8asize: number; v1: bigint; v2: bigint; v3: bigint; v4: bigint } {
  const state = {
    seed,
    u8a: new Uint8Array(32),
    u8asize: 0,
    v1: seed + P64_1 + P64_2,
    v2: seed + P64_2,
    v3: seed,
    v4: seed - P64_1
  };

  if (input.length < 32) {
    state.u8a.set(input);
    state.u8asize = input.length;
    return state;
  }

  const limit = input.length - 32;
  let p = 0;
  if (limit >= 0) {
    const adjustV = (v: bigint) => P64_1 * rotl(v + P64_2 * fromU8a(input, p, 4), _31n);
    do {
      state.v1 = adjustV(state.v1); p += 8;
      state.v2 = adjustV(state.v2); p += 8;
      state.v3 = adjustV(state.v3); p += 8;
      state.v4 = adjustV(state.v4); p += 8;
    } while (p <= limit);
  }

  if (p < input.length) {
    state.u8a.set(input.subarray(p, input.length));
    state.u8asize = input.length - p;
  }

  return state;
}

function xxhash64(input: Uint8Array, initSeed: number): Uint8Array {
  const { seed, u8a, u8asize, v1, v2, v3, v4 } = xxhashInit(BigInt(initSeed), input);
  let p = 0;
  let h64 = U64 & (BigInt(input.length) + (input.length >= 32
    ? (((((((((rotl(v1, _1n) + rotl(v2, _7n) + rotl(v3, _12n) + rotl(v4, _18n)) ^ (P64_1 * rotl(v1 * P64_2, _31n))) * P64_1 + P64_4) ^ (P64_1 * rotl(v2 * P64_2, _31n))) * P64_1 + P64_4) ^ (P64_1 * rotl(v3 * P64_2, _31n))) * P64_1 + P64_4) ^ (P64_1 * rotl(v4 * P64_2, _31n))) * P64_1 + P64_4)
    : (seed + P64_5)));

  while (p <= (u8asize - 8)) {
    h64 = U64 & (P64_4 + P64_1 * rotl(h64 ^ (P64_1 * rotl(P64_2 * fromU8a(u8a, p, 4), _31n)), _27n));
    p += 8;
  }
  if ((p + 4) <= u8asize) {
    h64 = U64 & (P64_3 + P64_2 * rotl(h64 ^ (P64_1 * fromU8a(u8a, p, 2)), _23n));
    p += 4;
  }
  while (p < u8asize) {
    h64 = U64 & (P64_1 * rotl(h64 ^ (P64_5 * BigInt(u8a[p++])), _11n));
  }
  h64 = U64 & (P64_2 * (h64 ^ (h64 >> _33n)));
  h64 = U64 & (P64_3 * (h64 ^ (h64 >> _29n)));
  h64 = U64 & (h64 ^ (h64 >> _32n));

  const result = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    result[i] = Number(h64 % _256n);
    h64 = h64 / _256n;
  }
  return result;
}

export function twox(data: Uint8Array, rounds: number): Uint8Array {
  const result = new Uint8Array(rounds * 8);
  for (let seed = 0; seed < rounds; seed++) {
    result.set(xxhash64(data, seed).reverse(), seed * 8);
  }
  return result;
}

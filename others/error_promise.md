# JavaScript 中的 try catch

在 JavaScript 中 使用 try catch 来捕获错误十分的丑陋，尤其是在异步代码中，错误的捕获和处理更是一件头疼的事情。

```ts
function catchError<T, E extends new (message?: string) => Error>(
  p: Promise<T>,
  errors: E[]
): Promise<[undefined, T] | [InstanceType<E>]> {
  return p
    .then((data) => [undefined, data] as [undefined, T])
    .catch((err) => {
      if (err === undefined) return [err]
      if (errors.some((e) => err instanceof e)) return [err]
      throw err
    })
}

type User = { id: number; name: string }

class InvalidIdError extends Error {
  constructor(message?: string) {
    super(message)
    this.name = 'InvalidIdError'
  }
}

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function getUser(id: number): Promise<User> {
  await wait(1000)
  if (id === 0) throw new InvalidIdError('Invalid id')
  return { id, name: 'User' }
}

async function main() {
  const [err, user] = await catchError(getUser(0), [InvalidIdError])
  if (err) {
    console.error(err)
    return
  }
  console.log(user)
}

main()
```

上面的代码中，我们定义了一个 `catchError` 函数，这种处理错误的方式类似于 Go 语言中的错误处理方式，通过返回一个元组来判断是否有错误发生。

避免了使用 try catch 来捕获错误，在 try catch 中暴露对象的方式只能是使用 let 来声明一个变量，然后在 catch 中使用，这样会导致变量的作用域变得很大，而且在异步代码中，错误的捕获和处理更是一件头疼的事情。

参见：<https://www.youtube.com/watch?v=AdmGHwvgaVs&list=WL>

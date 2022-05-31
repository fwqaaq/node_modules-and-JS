# [StreamsAPI](https://streams.spec.whatwg.org/#locked-to-a-reader)

> StreamsAPI解决的是Web应用程序如何消费有序的小信息块而不是大块信息

* 大块数据可能不会一次性都可以用.网络请求的响应就是一个典型的例子.网络负载以连续信息包形式交付,流式处理可以让应用在数据一到达就能使用
* 大块数据可能需要分小部分处理.视频处理,数据压缩,图像编码和JSON解析都是可以分成小部分处理

## 理解流

1. **可读流**:可以通过某个公共接口读取数据块的流.数据在内部从底层源进入流然后由消费者(`consumer`)进行处理
2. **可写流**:可以通过某个公共接口写入的数据块的流.生产者(`producer`)将数据写入流,数据在内部传入底层数据槽(`sink`)
3. **转换流**:由两种流构成,可写流用于接收数据(可写流),可读流用于输出数据(可读流).这两个流之间是转换程序(`transform`),可以根据需要检查和修改内容

>块(chunk)

* 流的基本单位是块(chunk).块可以是任意数据类型,但通常是定型数组.块不是固定的大小,也不一定按固定间隔到达(好的流需要考虑边界情况)
* 由于数据进出的速率不同,可能会出现不匹配的情况
   1. 流出口的处理数据的速度比入口提供数据的速度快.流出口空闲,浪费一点内存资源,可以接受
   2. 流入和流出均衡(理想)
   3. 流入口提供数据的速度比出口处理数据的速度快.这种不平衡的问题会造成某个地方数据积压,流需要做出处理
* <span style="background:red">所有流都会为已进入流但是尚未离开流的块提供一个内部队列</span>.在均衡流中,这个内部队列只会由0或者少量排队的块
  * 如果块入列的速度快于出列的速度,则内部队列会不断的增大.流会阻止这种情况,因此他会使用**背压(backpress)**通知流入口停止放送数据,直到队列大小降到某一个既定的阈值之下.这个值由排列策略决定了内部队列可以占用了多大的内存,即**高水位线(high water mask)**

## ReadableStream

* ReadableStream呈现一个可读取的二进制流操作.[Fetch API](https://www.ruanyifeng.com/blog/2020/12/fetch-tutorial.html)通过`Response`属性body提供了一个具体的`ReadableStream`对象

### 构造函数

>`new ReadableStream(underlyingSource[, queueingStrategy])`
  
* `underlyingSource`:定义构造流的行为方法和属性对象.
   1. `start(controller)`:当对象被构造是立刻调用的方法.此方法的内容由开发人员定义.用于访问六,并执行其他任何必须的设置流的功能.
      * 如果这个过程是异步完成的,它可以返回一个promise,表明成功或者失败
      * 这个方法的`controller`是一个[ReadableStreamDefaultController](https://developer.mozilla.org/en-US/docs/Web/API/ReadableStreamDefaultController)或者[ReadableByteStreamController](https://developer.mozilla.org/en-US/docs/Web/API/ReadableByteStreamController)具体取决于`type`属性的值
   2. `pull(controller)?`:由开发人员定义.当流的内部队列不满时,会重复调用这个方法,直到队列补满.
      * 如果`pull()`返回一个promise,那么它将不会再被调用,直到promise完成或者失败,该流将会出现错误
      * controller参数和start一样
   3. `cancel(reason)?`:如果应用程序标识该流将被取消(例如调用`ReadableStream.cancel()`),则将调用此方法,该方法由开发人员定义.
      * 该方法应该做任何必要的事情来释放对流的访问
      * 如果这个过程是异步的,它可以返回一个promise,表明成功或者失败
   4. `type?`:该睡醒控制正在处理的可读类型的流.如果她包含一个设置为`bytes`的值,则传递的控制器对象将是一个`ReadableByteStreamController`,能够处理BYOB(带你自己的缓冲区)/字节流
      * 如果未包含(**默认情况下**),则传递的控制器将为 `ReadableStreamDefaultController`
   5. `autoAllocateChunkSize?`:对于字节流,开发人员可以使用正整数值设置autoAllocateChunkSize以打开流的自动分配功能
      * 启用此功能后,流实现将自动分配一个具有给定整数大小的`ArrayBuffer`,并调用底层源代码,就好像消费者正在使用BYOB阅读器一样
* `queueingStrategy?`:一个可选择定义流的排队策略的对象.这需要两个参数：
   1. `highWaterMark`:非负整数.这定义了在应用背压之前可以包含在内部队列中的块的总数
   2. `size(chunk)`:包含参数chunk的方法.这表示每个块使用的大小(**以字节为单位**).

> ReadableStreamDefaultController

* streamsapi的一个接口,允许控制`ReadableStream`的状态和队列,默认控制器用于不是字节流的流

* 该实例会在`pull`或者`start`期间自动创建

* 属性:`desiredSize`:返回填充满流的内部队列所需要的大小,如果队列过满,可能是负数
* 方法: 并且 如果源对象不是`ReadableStreamDefaultController`则抛出TypeError错误.
  * `close()`:关闭关联的流.读取器将仍然可以从流中读取任何先前排队的块,但是一旦读取这些块,流将被关闭
    * 如果你想完全的摆脱流并且抱起任何排队的块,你可以使用`ReadableStream.cancel()` 或者`ReadableStreamDefaultReader.cancel()`
  * `enqueue()`:将给定的块送入关联的流
  * `error()`:导致任何未来与关联流交互都会出错

```js
async function* ints() {
  for (let i = 0; i < 5; i++) {
    yield await new Promise(resolve => setTimeout(() => resolve(i), 1000));
  }
}

const readableStream = new ReadableStream({
  async start(controller) {
    for await (const i of ints()) {
      await controller.enqueue(i)
    }
    await controller.close()
  }
})
```

### 属性

>`locked`:布尔值.只读属性返回可读流是否锁定到reader

* 一个可读流最多可以有一个激活的`reader`,并且直到被释放之前都是锁定到该`reader`
* 可以使用 [`ReadableStream.getReader()`](/zh-CN/docs/Web/API/ReadableStream/getReader) 方法获取读取器并且使用`releaseLock()`方法发布读取器

```js
console.log(readableStream.locked)
//该reader实例的read()可读出值
const readableStreamDefaultReader = readableStream.getReader()
console.log(readableStream.locked)
```

### 方法

>`getReader(mode?)`:该方法会创建一个reader,并将流锁定.只有当前reader释放后,其他reader才能使用

* `mode`:一般用来指定要创建的`reader`的类型.
  * `byob`:返回结果为`ReadableStreamBYOBReader`,可读取可读字节流
  * `undefined`:(或者不指定).返回结果为`ReadableStreamDefaultReader`.可以从流中返回单个块

返回值取决于`mode`:可能是`ReadableStreamBYOBReader`或者`ReadableStreamDefaultReader`

> `cancel(reason?)`:方法在流被取消后,返回**promise**

* 当你完全完成流并且不需要来自它的任何数据时使用取消,即使有排队等待的数据块.调用cancel后该数据丢失,并且流不再可读.
* 为了仍然可以读这些数据块并且而不是完全摆脱流,你应该使用`ReadableStreamDefaultController.close()`

* `reason`:取消原因.

>`pipeThrough(transformStream, options?)`:提供了一种链式的方式,将当前流通过转换流或者任何其他可写/可读流进行管道传输

* `transformStream`: 一个由可读流和可写流组成的`TransformStream`(或者结构为 `{writable, readable}` 的对象),他们共同工作将一些数据转化为另一些数据.
  * `writable`写入的数据在某些状态下可以被`readable`读取.例如,`TextDecoder`从中写入字节并读取字符,而视频解码器写入编码后的字节并从中读取未压缩的视频帧.
* `options`:管道至`writable`应该被使用的选项.可用选项是:
   1. `preventClose`:如果设置为`true`,源`ReadableStream`关闭将不再导致目标`WritableStream`关闭.一旦进程完成,该方法将返回一个兑现的`promise`,除非在关闭目标时遇到错误,在这种情况下下,它将因为该错误被拒绝.
   2. `preventAbort`:如果设置为`true`,目标`WritableStream`的错误将不再取消源`ReadableStream`.该方法将会返回一个因源错误而被拒绝的`promise`,或者任何在中止目标期间的错误.
   3. `preventCancel`:如果设置为`true`,目标`WritableStream`的错误将不在取消源`ReadableStream`.在这种情况下,该方法将会返回一个因源错误而被拒绝的`promise`,或者任何在中止目标期间的错误.此外,如果目标可读流开始关闭或者正在关闭,源可写流将不再被关闭.在这种情况下,方法将返回一个拒绝并带有错误的`promise`,或者任何在中止目标期间的错误,来表明管道关闭失败.
   4. `signal`:如果设置一个 `AbortSignal` 对象,然后可以通过相应的`AbortController`中止正在进行的管道操作

>`pipeTo(destination, options?)`:通过管道将当前的`ReadableStream`输出到给定的`WritableStream`当管道成功完成时返回一个成功状态的promise

* `destination`: 充当`ReadableStream`最终目标的`WriteableStream`
* `options`:和`pipeThrough`的options一样

## ReadableStreamDefaultReader

>Streams API的`ReadableStreamDefaultReader`的接口,表示一个可被用于读取来自网络提供的流数据(例如 fetch 请求)

### ReadableStreamDefaultReader构造函数

>`new ReadableStreamDefaultReader(stream)`:创造并且返回一个ReadableStreamDefaultReader实例对象

* <sapn style="background:red">注意:通常你不需要手动构造,你只需要使用`ReadableStream.getReader()`方法</sapn>

```js
//消费
(
  async function(){
    while(true){
      const { done, value} = await readableStreamDefaultReader.read()
      if(done){
        break
      }else{
        console.log(value)
      }
    }
  }
)()
```

* `stream`:一个将要被读取的`readableStream`

### ReadableStreamDefaultReader属性

>`closed`:**只读**.在流关闭时,返回一个兑现的promise,或者在流抛出错误或者 reader 的所被释放时拒绝

```js
reader.closed.then(() => {
  console.log('reader closed');
})
```

### ReadableStreamDefaultReader方法

* `cancel(reason?)`:如果reader是激活状态,`cancel()`方法的行为和关联流`ReadableStream.cancel()`的行为相同
* `read()`:返回一个对流内部对流中下一个块的使用权的promise.promise的状态取决于流的状态
  * 如果一个块可用,则 promise 将使用 `{ value: theChunk, done: false }` 形式的对象来兑现
  * 如果流关闭,则 promise 将使用 `{ value: undefined, done: true }` 形式的对象来兑现
  * 如果流发生错误,promise 将因相关错误被拒绝
* `releaseLock()`:没有参数,也没有返回值.释放 reader 对流的锁定
  * 如果释放锁时关联流出错,reader 随后会以同样的方式发生错误
  * reader的所在仍有到处理的读取请求时无法释放,即`reade()`返回的promise尚未完成
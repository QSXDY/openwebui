<script lang="ts">
	import DOMPurify from 'dompurify';

	import { onMount, getContext, createEventDispatcher, onDestroy } from 'svelte';
	import * as FocusTrap from 'focus-trap';
	import { subscriptionPurchase, SubscriptionPayments } from '$lib/apis/setmenu';
	const i18n = getContext('i18n');
	const dispatch = createEventDispatcher();

	import { fade } from 'svelte/transition';
	import { flyAndScale } from '$lib/utils/transitions';

	import { marked } from 'marked';
	export let menu;
	export let title = '';
	export let message = null;
	import { toast } from 'svelte-sonner';
	export let cancelLabel = $i18n.t('Cancel');
	export let confirmLabel = $i18n.t('Confirm');
	let qrCodeDataUrl = '';
	export let onConfirm = () => {};

	export let input = false;
	export let inputPlaceholder = '';
	export let inputValue = '';

	export let show = false;
	export let payType = 'alipay'; // "alipay" | "wechat"
	export let qrCodeUrl = {
		qrCodeUrl: '',
		trade_no: ''
	}; // 二维码图片地址

	export let onJump = () => {};

	let modalElement = null;
	let mounted = false;

	let focusTrap: FocusTrap.FocusTrap | null = null;

	const onPayTypeChange = (type: string) => {
		if (payType == type) {
			return;
		} else {
			payType = type;
			dinggou();
		}
	};

	const handleKeyDown = (event: KeyboardEvent) => {
		if (event.key === 'Escape') {
			console.log('Escape');
			show = false;
		}

		if (event.key === 'Enter') {
			console.log('Enter');
			confirmHandler();
		}
	};

	const confirmHandler = async () => {
		show = false;
		await onConfirm();
		dispatch('confirm', inputValue);
	};

	onMount(() => {
		mounted = true;
	});

	const dinggou = async () => {
		try {
			const res = await subscriptionPurchase(localStorage.token, menu.id, payType).catch(
				(error) => {
					toast.error(`${error}`);
					return null;
				}
			);

			if (res) {
				console.log('订购套餐', res.detail);
				qrCodeUrl.trade_no = res.id;
				if (res.detail.qrcode) {
					document.getElementById('trade-qrcode').innerHTML = '';
					new QRCode(document.getElementById('trade-qrcode'), {
						text: res.detail.qrcode,
						width: 128,
						height: 128,
						colorDark: '#000000',
						colorLight: '#ffffff',
						correctLevel: QRCode.CorrectLevel.H
					});
				} else {
					toast.error('未获取到支付链接，无法生成二维码');
					qrCodeUrl.qrCodeUrl = '';
				}
			}
		} catch (err) {
			console.error(err);
		}
	};

	$: if (menu) {
		dinggou();
		payType = 'alipay';
	}

	onDestroy(() => {
		show = false;
	});

	const ashuda = async () => {
		console.log('你好111111');
		try {
			const res = await SubscriptionPayments(localStorage.token, qrCodeUrl.trade_no).catch(
				(error) => {
					toast.error(`${error}`);
					return null;
				}
			);

			if (res) {
				console.log('获取订购套餐详情', res.detail);
			}
		} catch (err) {
			console.error(err);
		}
	};
</script>

{#if show}
	<!-- svelte-ignore a11y-click-events-have-key-events -->
	<!-- svelte-ignore a11y-no-static-element-interactions -->
	<div
		bind:this={modalElement}
		class=" fixed top-0 right-0 left-0 bottom-0 bg-black/60 w-full h-screen max-h-[100dvh] flex justify-center z-99999999 overflow-hidden overscroll-contain"
		on:mousedown={() => {
			show = false;
		}}
	>
		<div
			class=" m-auto rounded-2xl max-w-full w-[32rem] mx-2 bg-gray-50 dark:bg-gray-950 max-h-[100dvh] shadow-3xl"
			in:flyAndScale
			on:mousedown={(e) => {
				e.stopPropagation();
			}}
		>
			<div class="px-[1.75rem] py-6 flex flex-col">
				<div class=" text-lg flex justify-between font-semibold dark:text-gray-200 mb-2.5">
					{#if title !== ''}
						{title}
					{:else}
						{$i18n.t('Order Package')}
					{/if}
					<button
						class="self-center"
						on:click={() => {
							show = false;
						}}
					>
						<svg
							xmlns="http://www.w3.org/2000/svg"
							viewBox="0 0 20 20"
							fill="currentColor"
							class="w-5 h-5"
						>
							<path
								d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z"
							/>
						</svg>
					</button>
				</div>
				<div class="w-full max-w-md mx-auto">
					<div class="flex flex-col justify-between">
						<div class="text-lg font-bold mb-2">套餐名称：{menu.name}</div>
						<div class="text-lg font-bold mb-2">
							套餐额度： {menu.credits}积分<span class="text-base font-normal text-gray-500"
								>/天</span
							>
						</div>
					</div>
					<div class="text-3xl font-extrabold mb-4">
						<span class="text-lg font-bold">套餐价格：</span> ${menu.price}
						<span class="text-base font-normal text-gray-500">/ {menu.duration}天</span>
					</div>

					<div class="text-center text-gray-700 font-medium mb-4">
						{$i18n.t('Please select a payment method')}
					</div>
					<div class="flex gap-4 mb-6">
						<div
							class="flex-1 border rounded-xl p-4 flex flex-col items-center cursor-pointer transition-all"
							class:bg-blue-50={payType === 'alipay'}
							class:border-blue-500={payType === 'alipay'}
							on:click={() => onPayTypeChange('alipay')}
						>
							<svg
								t="1748247940029"
								class="w-10 h-10 mb-2"
								viewBox="0 0 1024 1024"
								version="1.1"
								xmlns="http://www.w3.org/2000/svg"
								p-id="6389"
								width="200"
								height="200"
								><path
									d="M860.009412 1.445647H164.020706A163.779765 163.779765 0 0 0 0 165.044706v693.940706c0 90.322824 73.396706 163.568941 164.020706 163.568941h695.988706A163.749647 163.749647 0 0 0 1024 858.985412v-6.686118s-266.360471-110.712471-400.835765-175.194353c-90.202353 110.682353-206.576941 177.844706-327.378823 177.844706-204.318118 0-273.709176-178.266353-176.941177-295.634823 21.082353-25.6 56.982588-49.995294 112.670118-63.698824 87.100235-21.323294 225.761882 13.312 355.689412 56.079059a709.993412 709.993412 0 0 0 57.675294-140.559059H244.404706v-40.448h206.486588V298.164706H200.824471V257.686588h250.096941V154.262588s0-17.438118 17.709176-17.438117h100.924236v120.862117h247.265882V298.164706h-247.265882v72.493176h201.84847c-19.305412 78.878118-48.670118 151.491765-85.473882 215.250824 61.259294 22.106353 116.254118 43.038118 157.214117 56.711529C990.539294 691.832471 1024 694.512941 1024 694.512941V165.044706A163.749647 163.749647 0 0 0 860.009412 1.445647zM248.892235 556.122353c-25.569882 2.529882-73.607529 13.824-99.870117 36.954353-78.727529 68.457412-31.623529 193.566118 127.668706 193.566118 92.581647 0 185.133176-59.030588 257.807058-153.569883-103.363765-50.266353-190.976-86.256941-285.605647-76.950588z"
									fill="#1296db"
									p-id="6390"
								></path></svg
							>
							<div class="font-bold text-blue-600">{$i18n.t('Alipay')}</div>
							<div class="text-xs text-gray-400">Alipay payment</div>
						</div>
						<div
							class="flex-1 border rounded-xl p-4 flex flex-col items-center cursor-pointer transition-all"
							class:bg-green-50={payType === 'wxpay'}
							class:border-green-500={payType === 'wxpay'}
							on:click={() => onPayTypeChange('wxpay')}
						>
							<svg
								t="1748247856456"
								viewBox="0 0 1024 1024"
								version="1.1"
								xmlns="http://www.w3.org/2000/svg"
								p-id="5406"
								class="w-10 h-10 mb-2"
								><path
									d="M896 0H128C57.58976 0 0 57.58976 0 128v768C0 966.41024 57.58976 1024 128 1024h768c70.41024 0 128-57.58976 128-128V128C1024 57.58976 966.41024 0 896 0zM512 787.21024c-44.78976 0-83.21024-6.41024-121.58976-19.21024-25.6 12.8-64 44.78976-76.8 51.2-25.6 12.8-19.21024-12.8-19.21024-12.8l12.8-76.8c-76.8-51.2-121.61024-134.38976-121.61024-223.98976 0-160.01024 147.21024-288.01024 326.41024-288.01024 108.81024 0 211.18976 51.2 268.8 121.61024L460.8 486.4s-25.6 12.8-51.2-6.38976l-51.2-38.4s-38.4-32.01024-19.21024 19.18976l51.2 115.2s6.41024 31.98976 44.81024 12.8c32.01024-12.8 268.8-159.98976 371.2-217.6 19.21024 38.4 31.98976 83.21024 31.98976 128 0 153.6-147.18976 288.01024-326.38976 288.01024z"
									fill="#48B338"
									p-id="5407"
								></path></svg
							>
							<div class="font-bold text-green-600">{$i18n.t('WeChat')}</div>
							<div class="text-xs text-gray-400">WeChat Pay</div>
						</div>
					</div>
					<div class="text-blue-600 font-bold text-center mb-2">
						请使用{payType === 'alipay' ? '支付宝' : '微信'}扫码支付
					</div>
					<div class="text-xs text-gray-400 text-center mb-2">
						打开{payType === 'alipay' ? '支付宝' : '微信'}APP，扫一扫下方二维码
					</div>
					<div class="flex justify-center mb-2">
						<!-- <img
						src={qrCodeUrl.qrCodeUrl}
						alt="二维码"
						class="w-40 h-40 bg-white p-2 rounded-lg border"
					/> -->
						<div id="trade-qrcode" class="h-[128px] w-[128px]"></div>
					</div>
					<div class="text-center text-gray-700 mb-2">
						金额: <span class="font-bold">${menu.price}</span>
					</div>
					<div class=" text-gray-400 text-center cursor-pointer" on:click={ashuda}>
						支付后请点击此处手动刷新
					</div>
				</div>
			</div>
		</div>
	</div>
{/if}

<style>
	.modal-content {
		animation: scaleUp 0.1s ease-out forwards;
	}

	@keyframes scaleUp {
		from {
			transform: scale(0.985);
			opacity: 0;
		}
		to {
			transform: scale(1);
			opacity: 1;
		}
	}
</style>

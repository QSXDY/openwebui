<script lang="ts">
	// 导入所需的依赖
	import DOMPurify from 'dompurify';
	import { onMount, getContext, createEventDispatcher, onDestroy } from 'svelte';
	import * as FocusTrap from 'focus-trap';
	import { toast } from 'svelte-sonner';
	import { fade } from 'svelte/transition';
	import { flyAndScale } from '$lib/utils/transitions';
	import { marked } from 'marked';
	import { subscriptionRedeem } from '$lib/apis/setmenu';

	// 获取i18n上下文和创建事件分发器
	const i18n = getContext('i18n');
	const dispatch = createEventDispatcher();

	// 组件属性定义
	export let title = '';
	export let message = '';
	export let cancelLabel = $i18n.t('Cancel');
	export let confirmLabel = $i18n.t('exchange-text');
	export let onConfirm = () => {};
	export let input = false;
	export let inputPlaceholder = '';
	export let inputValue = '';
	export let show = false;

	// 组件内部状态
	let modalElement = null;
	let mounted = false;
	let focusTrap: FocusTrap.FocusTrap | null = null;

	// 处理键盘事件
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

	// 处理确认按钮点击
	const confirmHandler = async () => {
		if (!inputValue) {
			return;
		}
		show = false;
		try {
			// 调用兑换码API
			const res = await subscriptionRedeem(localStorage.token, inputValue).catch((error) => {
				toast.error(`${error}`);
				return null;
			});

			if (res) {
				console.log('兑换码使用', res);
				toast.success(`${res.message}`);
				await onConfirm();
				dispatch('confirm', inputValue);
			}
		} catch (err) {
			console.error(err);
		}

		return;
	};

	// 组件挂载时的处理
	onMount(() => {
		mounted = true;
		inputValue = '';
	});

	// 响应式处理模态框显示/隐藏
	$: if (mounted) {
		if (show && modalElement) {
			// 显示模态框时的处理
			document.body.appendChild(modalElement);
			focusTrap = FocusTrap.createFocusTrap(modalElement);
			focusTrap.activate();

			window.addEventListener('keydown', handleKeyDown);
			document.body.style.overflow = 'hidden';
		} else if (modalElement) {
			// 隐藏模态框时的处理
			focusTrap.deactivate();
			window.removeEventListener('keydown', handleKeyDown);
			document.body.removeChild(modalElement);
			document.body.style.overflow = 'unset';
		}
	}

	// 组件销毁时的清理
	onDestroy(() => {
		show = false;
		if (focusTrap) {
			focusTrap.deactivate();
		}
		if (modalElement) {
			document.body.removeChild(modalElement);
		}
	});
</script>

{#if show}
	<!-- svelte-ignore a11y-click-events-have-key-events -->
	<!-- svelte-ignore a11y-no-static-element-interactions -->
	<!-- 模态框遮罩层 -->
	<div
		bind:this={modalElement}
		class=" fixed top-0 right-0 left-0 bottom-0 bg-black/60 w-full h-screen max-h-[100dvh] flex justify-center z-99999999 overflow-hidden overscroll-contain"
		in:fade={{ duration: 10 }}
		on:mousedown={() => {
			show = false;
		}}
	>
		<!-- 模态框内容 -->
		<div
			class=" m-auto rounded-2xl max-w-full w-[32rem] mx-2 bg-gray-50 dark:bg-gray-950 max-h-[100dvh] shadow-3xl"
			in:flyAndScale
			on:mousedown={(e) => {
				e.stopPropagation();
			}}
		>
			<div class="px-[1.75rem] py-6 flex flex-col">
				<!-- 标题 -->
				<div class=" text-lg font-semibold dark:text-gray-200 mb-2.5">
					{#if title !== ''}
						{title}
					{:else}
						{$i18n.t('exchangecode-title')}
					{/if}
				</div>

				<slot>
					<!-- 输入框区域 -->
					<div class=" text-sm text-gray-500 flex-1">
						<textarea
							bind:value={inputValue}
							placeholder={inputPlaceholder
								? inputPlaceholder
								: $i18n.t('exchangecode-description')}
							class="w-full mt-2 rounded-lg px-4 py-2 text-sm dark:text-gray-300 dark:bg-gray-900 outline-hidden resize-none"
							rows="3"
							required
						/>
					</div>
				</slot>

				<!-- 按钮区域 -->
				<div class="mt-6 flex justify-between gap-1.5">
					<!-- 取消按钮 -->
					<button
						class="bg-gray-100 hover:bg-gray-200 text-gray-800 dark:bg-gray-850 dark:hover:bg-gray-800 dark:text-white font-medium w-full py-2.5 rounded-lg transition"
						on:click={() => {
							show = false;
							dispatch('cancel');
						}}
						type="button"
					>
						{cancelLabel}
					</button>
					<!-- 确认按钮 -->
					<button
						class="bg-gray-900 hover:bg-gray-850 text-gray-100 dark:bg-gray-100 dark:hover:bg-white dark:text-gray-800 font-medium w-full py-2.5 rounded-lg transition"
						on:click={() => {
							confirmHandler();
						}}
						type="button"
					>
						{confirmLabel}
					</button>
				</div>
			</div>
		</div>
	</div>
{/if}

<style>
	/* 模态框动画样式 */
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
